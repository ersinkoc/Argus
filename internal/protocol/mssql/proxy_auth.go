package mssql

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"unicode/utf16"
)

func ProxyAuthServer(client net.Conn) (username string, err error) {
	pp, err := ReadPacket(client)
	if err != nil {
		return "", fmt.Errorf("reading pre-login: %w", err)
	}
	if pp.Type != PacketPreLogin {
		return "", fmt.Errorf("expected pre-login (0x12), got 0x%02x", pp.Type)
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i*13 + 37)
	}
	pr := BuildProxyPreLoginResponse(nonce)
	if err := WritePacket(client, &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: pr}); err != nil {
		return "", fmt.Errorf("writing pre-login response: %w", err)
	}
	lp, err := ReadPacket(client)
	if err != nil {
		return "", fmt.Errorf("reading login7: %w", err)
	}
	if lp.Type != PacketTDS7Login {
		return "", fmt.Errorf("expected login7 (0x10), got 0x%02x", lp.Type)
	}
	u := extractLogin7Username(lp.Data)
	if u == "" {
		return "", fmt.Errorf("empty username")
	}
	return u, nil
}

func ProxyAuthClient(backend net.Conn, preLoginData []byte, user, pass string) ([]byte, error) {
	if err := WritePacket(backend, &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: preLoginData}); err != nil {
		return nil, fmt.Errorf("sending pre-login: %w", err)
	}
	pr, err := ReadPacket(backend)
	if err != nil {
		return nil, fmt.Errorf("reading pre-login response: %w", err)
	}
	nonce := extractPreLoginNonce(pr.Data)
	lp := BuildProxyLogin7(user, pass, nonce)
	if err := WritePacket(backend, lp); err != nil {
		return nil, fmt.Errorf("sending login7: %w", err)
	}
	lr, err := ReadPacket(backend)
	if err != nil {
		return nil, fmt.Errorf("reading login response: %w", err)
	}
	return lr.Data, nil
}

func BuildProxyLogin7(username, password string, nonce []byte) *Packet {
	uu := utf16.Encode([]rune(username))
	pp := utf16.Encode([]rune(password))
	ub := utf16ToBytes(uu)
	pb := utf16ToBytes(pp)
	ep := encryptTDSPassword(pb, nonce)

	hs := 94
	var vd []byte
	uo := hs + len(vd)
	vd = append(vd, ub...)
	po := hs + len(vd)
	vd = append(vd, ep...)

	h := make([]byte, hs)
	binary.LittleEndian.PutUint32(h[0:4], uint32(hs+len(vd)))
	binary.LittleEndian.PutUint32(h[4:8], 0x74000004)
	binary.LittleEndian.PutUint32(h[8:12], 0x74000004)
	binary.LittleEndian.PutUint32(h[12:16], 4096)
	binary.LittleEndian.PutUint32(h[20:24], 0x01000000)
	binary.LittleEndian.PutUint32(h[24:28], 1234)
	binary.LittleEndian.PutUint32(h[28:32], 0)
	h[36] = 0xE0
	h[39] = 0x0A
	h[42] = 0x00
	binary.LittleEndian.PutUint32(h[44:48], 0)
	binary.LittleEndian.PutUint32(h[48:52], 0x0409)
	setU16(h, 48, uint16(uo))
	setU16(h, 50, uint16(len(ub)/2))
	setU16(h, 52, uint16(po))
	setU16(h, 54, uint16(len(ep)))
	setStr(h, hs, &vd, 64, 66, "")
	setStr(h, hs, &vd, 68, 70, "")
	setStr(h, hs, &vd, 72, 74, "")
	setStr(h, hs, &vd, 76, 78, "")
	setStr(h, hs, &vd, 88, 90, "")
	return &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: append(h, vd...)}
}

func BuildProxyPreLoginResponse(nonce []byte) []byte {
	var d []byte
	d = append(d, 0x01, 0x01, 0x00, 0x01, 0x00)
	d = append(d, 0x04, 0x05, 0x00)
	d = append(d, byte(len(nonce)), 0x00)
	d = append(d, 0xFF)
	d[5] = 8
	d[6] = 0
	d = append(d, 1)
	d = append(d, nonce...)
	return d
}

func ForwardLoginResponse(client net.Conn, data []byte) error {
	return WritePacket(client, &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: data})
}

func setU16(data []byte, off int, v uint16) {
	binary.LittleEndian.PutUint16(data[off:off+2], v)
}

func setStr(header []byte, hs int, vdp *[]byte, oo, lo int, s string) {
	b := utf16ToBytes(utf16.Encode([]rune(s)))
	off := hs + len(*vdp)
	*vdp = append(*vdp, b...)
	binary.LittleEndian.PutUint16(header[oo:oo+2], uint16(off))
	binary.LittleEndian.PutUint16(header[lo:lo+2], uint16(len(b)))
}

func extractPreLoginNonce(data []byte) []byte {
	i := 0
	for i < len(data) {
		t := data[i]
		if t == 0xFF {
			break
		}
		i++
		if i+3 >= len(data) {
			break
		}
		off := int(binary.LittleEndian.Uint16(data[i:i+2]))
		ln := int(binary.LittleEndian.Uint16(data[i+2:i+4]))
		i += 4
		if t == 0x04 && off+ln <= len(data) {
			return data[off : off+ln]
		}
	}
	return nil
}

func encryptTDSPassword(passUTF16 []byte, nonce []byte) []byte {
	h := sha256.Sum256(passUTF16)
	e := make([]byte, len(h))
	for i := range h {
		if len(nonce) > 0 {
			e[i] = h[i] ^ nonce[i%len(nonce)]
		} else {
			e[i] = h[i]
		}
	}
	return e
}

func utf16ToBytes(runes []uint16) []byte {
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}
