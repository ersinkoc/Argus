package mssql

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTDSTLSHandshakeConnWriteSmallFrame(t *testing.T) {
	underlying := &tdsTLSMemoryConn{maxWrite: 3}
	conn := NewTDSTLSHandshakeConn(underlying)

	for _, payload := range [][]byte{[]byte("hello"), []byte("bye")} {
		n, err := conn.Write(payload)
		if err != nil {
			t.Fatalf("Write(%q): %v", payload, err)
		}
		if n != len(payload) {
			t.Fatalf("Write(%q) = %d, want %d", payload, n, len(payload))
		}
	}

	want := []byte{
		PacketPreLogin, StatusEOM, 0, 13, 0, 0, 1, 0,
		'h', 'e', 'l', 'l', 'o',
		PacketPreLogin, StatusEOM, 0, 11, 0, 0, 2, 0,
		'b', 'y', 'e',
	}
	if got := underlying.written.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("wire bytes:\n got % x\nwant % x", got, want)
	}
}

func TestTDSTLSHandshakeConnWriteSplitsAndReassembles(t *testing.T) {
	payload := make([]byte, 2*tdsTLSMaxPayload+17)
	for i := range payload {
		payload[i] = byte(i)
	}

	underlying := &tdsTLSMemoryConn{maxWrite: 97}
	conn := NewTDSTLSHandshakeConn(underlying)
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}

	wire := underlying.written.Bytes()
	var reassembled []byte
	for packetIndex, offset := 0, 0; offset < len(wire); packetIndex++ {
		if len(wire)-offset < headerSize {
			t.Fatalf("packet %d has truncated header", packetIndex)
		}
		header := wire[offset : offset+headerSize]
		packetLen := int(binary.BigEndian.Uint16(header[2:4]))
		if packetLen > tdsTLSMaxPacketSize {
			t.Errorf("packet %d length = %d, want <= %d", packetIndex, packetLen, tdsTLSMaxPacketSize)
		}
		if packetLen < headerSize || offset+packetLen > len(wire) {
			t.Fatalf("packet %d has invalid length %d", packetIndex, packetLen)
		}
		if header[0] != PacketPreLogin {
			t.Errorf("packet %d type = 0x%02x, want PRELOGIN", packetIndex, header[0])
		}
		if wantID := byte(packetIndex + 1); header[6] != wantID {
			t.Errorf("packet %d ID = %d, want %d", packetIndex, header[6], wantID)
		}

		last := offset+packetLen == len(wire)
		wantStatus := StatusNormal
		if last {
			wantStatus = StatusEOM
		}
		if header[1] != wantStatus {
			t.Errorf("packet %d status = 0x%02x, want 0x%02x", packetIndex, header[1], wantStatus)
		}
		reassembled = append(reassembled, wire[offset+headerSize:offset+packetLen]...)
		offset += packetLen
	}

	if !bytes.Equal(reassembled, payload) {
		t.Fatal("reassembled payload differs from input")
	}
}

func TestTDSTLSHandshakeConnPacketIDSkipsZeroOnRollover(t *testing.T) {
	underlying := &tdsTLSMemoryConn{}
	conn := NewTDSTLSHandshakeConn(underlying)
	conn.packetID = 254

	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if _, err := conn.Write([]byte("b")); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	wire := underlying.written.Bytes()
	if got := wire[6]; got != 255 {
		t.Errorf("first packet ID = %d, want 255", got)
	}
	if got := wire[headerSize+1+6]; got != 1 {
		t.Errorf("second packet ID = %d, want 1", got)
	}
}

func TestTDSTLSHandshakeConnReadInitialPacketThenRawHandshakeBytes(t *testing.T) {
	wire := append(tdsTLSTestPacket(PacketPreLogin, StatusEOM, 7, []byte("first")), []byte("second-flight")...)
	underlying := &tdsTLSMemoryConn{readData: wire, maxRead: 2}
	conn := NewTDSTLSHandshakeConn(underlying)

	want := []byte("firstsecond-flight")
	got := make([]byte, 0, len(want))
	bufferSizes := []int{1, 4, 2, 9, 3}
	for i := 0; len(got) < len(want); i++ {
		buf := make([]byte, bufferSizes[i%len(bufferSizes)])
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read after %d bytes: %v", len(got), err)
		}
		if n == 0 {
			t.Fatal("Read returned no data and no error")
		}
		got = append(got, buf[:n]...)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("read bytes = %q, want %q", got, want)
	}
}

func TestTDSTLSHandshakeConnReadRejectsWrongPacketType(t *testing.T) {
	underlying := &tdsTLSMemoryConn{readData: tdsTLSTestPacket(PacketReply, StatusEOM, 1, []byte("not TLS"))}
	conn := NewTDSTLSHandshakeConn(underlying)

	_, err := conn.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), "unexpected TDS packet type") {
		t.Fatalf("Read error = %v, want unexpected packet type", err)
	}
}

func TestTDSTLSHandshakeConnReadPropagatesInvalidLength(t *testing.T) {
	header := []byte{PacketPreLogin, StatusEOM, 0, 7, 0, 0, 1, 0}
	conn := NewTDSTLSHandshakeConn(&tdsTLSMemoryConn{readData: header})

	_, err := conn.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), "invalid TDS packet length: 7") {
		t.Fatalf("Read error = %v, want invalid TDS packet length", err)
	}
}

func TestTDSTLSHandshakeConnPassthroughPreservesPendingData(t *testing.T) {
	framed := tdsTLSTestPacket(PacketPreLogin, StatusEOM, 1, []byte("abc"))
	underlying := &tdsTLSMemoryConn{readData: append(framed, []byte("raw")...)}
	conn := NewTDSTLSHandshakeConn(underlying)

	one := make([]byte, 1)
	if n, err := conn.Read(one); err != nil || n != 1 || string(one) != "a" {
		t.Fatalf("first Read = (%d, %v, %q), want (1, nil, %q)", n, err, one, "a")
	}

	conn.FinishHandshake()

	pending := make([]byte, 2)
	if n, err := conn.Read(pending); err != nil || n != 2 || string(pending) != "bc" {
		t.Fatalf("pending Read = (%d, %v, %q), want (2, nil, %q)", n, err, pending, "bc")
	}
	raw := make([]byte, 3)
	if n, err := io.ReadFull(conn, raw); err != nil || n != 3 || string(raw) != "raw" {
		t.Fatalf("raw Read = (%d, %v, %q), want (3, nil, %q)", n, err, raw, "raw")
	}

	conn.SetPassthrough()
	if n, err := conn.Write([]byte("out")); err != nil || n != 3 {
		t.Fatalf("passthrough Write = (%d, %v), want (3, nil)", n, err)
	}
	if got := underlying.written.String(); got != "out" {
		t.Fatalf("passthrough wire bytes = %q, want %q", got, "out")
	}
}

func TestTDSTLSHandshakeConnDelegatesConnectionMethods(t *testing.T) {
	underlying := &tdsTLSMemoryConn{}
	conn := NewTDSTLSHandshakeConn(underlying)
	deadline := time.Unix(123, 456)
	readDeadline := deadline.Add(time.Second)
	writeDeadline := deadline.Add(2 * time.Second)

	if got := conn.LocalAddr(); got != underlying.localAddr {
		t.Fatalf("LocalAddr = %v, want %v", got, underlying.localAddr)
	}
	if got := conn.RemoteAddr(); got != underlying.remoteAddr {
		t.Fatalf("RemoteAddr = %v, want %v", got, underlying.remoteAddr)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := conn.SetReadDeadline(readDeadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := conn.SetWriteDeadline(writeDeadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if underlying.deadline != deadline || underlying.readDeadline != readDeadline || underlying.writeDeadline != writeDeadline {
		t.Fatalf("deadlines not delegated: got (%v, %v, %v)", underlying.deadline, underlying.readDeadline, underlying.writeDeadline)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !underlying.closed {
		t.Fatal("underlying connection was not closed")
	}
}

func TestTDSTLSHandshakeConnTLSHandshakeAndPassthrough(t *testing.T) {
	certificate := tdsTLSTestCertificate(t)
	clientSide, relayClient := net.Pipe()
	defer clientSide.Close()
	defer relayClient.Close()
	serverTransportConn, relayServer := net.Pipe()
	defer serverTransportConn.Close()
	defer relayServer.Close()

	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range []net.Conn{clientSide, relayClient, serverTransportConn, relayServer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	go relayODBCStyleTLSHandshake(t, relayServer, relayClient)

	serverTransport := NewTDSTLSHandshakeConn(serverTransportConn)
	serverTLS := tls.Server(serverTransport, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	clientTLS := tls.Client(clientSide, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})

	errorsCh := make(chan error, 2)
	go func() { errorsCh <- serverTLS.Handshake() }()
	go func() { errorsCh <- clientTLS.Handshake() }()
	for range 2 {
		if err := <-errorsCh; err != nil {
			t.Fatalf("TLS handshake: %v", err)
		}
	}

	serverTransport.FinishHandshake()

	serverResult := make(chan error, 1)
	go func() {
		request := make([]byte, 4)
		if _, err := io.ReadFull(serverTLS, request); err != nil {
			serverResult <- err
			return
		}
		if string(request) != "ping" {
			serverResult <- errors.New("server received unexpected application data")
			return
		}
		_, err := serverTLS.Write([]byte("pong"))
		serverResult <- err
	}()

	if _, err := clientTLS.Write([]byte("ping")); err != nil {
		t.Fatalf("client application Write: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(clientTLS, response); err != nil {
		t.Fatalf("client application Read: %v", err)
	}
	if string(response) != "pong" {
		t.Fatalf("client received %q, want %q", response, "pong")
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server application exchange: %v", err)
	}
}

func relayODBCStyleTLSHandshake(t *testing.T, serverSide, clientSide net.Conn) {
	t.Helper()
	defer serverSide.Close()
	defer clientSide.Close()

	buf := make([]byte, 65536)
	// First client handshake flight is wrapped in a PRELOGIN packet.
	n, err := clientSide.Read(buf)
	if err != nil {
		return
	}
	if _, err := serverSide.Write(tdsTLSTestPacket(PacketPreLogin, StatusEOM, 1, buf[:n])); err != nil {
		return
	}
	// First server handshake flight is also wrapped in PRELOGIN packets and may
	// span multiple packets. Reassemble and unwrap the entire flight before the
	// synthetic client tls.Conn sees it.
	n, err = serverSide.Read(buf)
	if err != nil {
		return
	}
	framed := append([]byte(nil), buf[:n]...)
	for {
		if len(framed) >= headerSize {
			total := 0
			complete := true
			allEOM := true
			for offset := 0; offset < len(framed); {
				if len(framed)-offset < headerSize {
					complete = false
					break
				}
				packetLen := int(binary.BigEndian.Uint16(framed[offset+2 : offset+4]))
				if packetLen < headerSize || offset+packetLen > len(framed) {
					complete = false
					break
				}
				if framed[offset+1]&StatusEOM == 0 {
					allEOM = false
				}
				total = offset + packetLen
				offset += packetLen
			}
			if complete && total == len(framed) && allEOM {
				break
			}
		}
		n, err = serverSide.Read(buf)
		if err != nil {
			return
		}
		framed = append(framed, buf[:n]...)
	}
	var payload []byte
	for offset := 0; offset < len(framed); {
		packetLen := int(binary.BigEndian.Uint16(framed[offset+2 : offset+4]))
		payload = append(payload, framed[offset+headerSize:offset+packetLen]...)
		offset += packetLen
	}
	if len(payload) > 0 {
		preview := payload
		if len(preview) > 8 {
			preview = preview[:8]
		}
		t.Logf("relay first server flight preview: % x", preview)
	}
	if _, err := clientSide.Write(payload); err != nil {
		return
	}
	// All subsequent bytes flow raw in both directions.
	go io.Copy(serverSide, clientSide)
	_, _ = io.Copy(clientSide, serverSide)
}

func tdsTLSTestPacket(packetType, status, packetID byte, payload []byte) []byte {
	packet := make([]byte, headerSize+len(payload))
	packet[0] = packetType
	packet[1] = status
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[6] = packetID
	copy(packet[headerSize:], payload)
	return packet
}

func tdsTLSTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tds-tls-test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}

type tdsTLSMemoryConn struct {
	readData      []byte
	readAt        int
	maxRead       int
	written       bytes.Buffer
	maxWrite      int
	closed        bool
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
	localAddr     net.Addr
	remoteAddr    net.Addr
}

func (c *tdsTLSMemoryConn) Read(p []byte) (int, error) {
	if c.readAt == len(c.readData) {
		return 0, io.EOF
	}
	if c.maxRead > 0 && len(p) > c.maxRead {
		p = p[:c.maxRead]
	}
	n := copy(p, c.readData[c.readAt:])
	c.readAt += n
	return n, nil
}

func (c *tdsTLSMemoryConn) Write(p []byte) (int, error) {
	if c.maxWrite > 0 && len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.written.Write(p)
}

func (c *tdsTLSMemoryConn) Close() error {
	c.closed = true
	return nil
}

func (c *tdsTLSMemoryConn) LocalAddr() net.Addr {
	if c.localAddr == nil {
		c.localAddr = tdsTLSTestAddr("local")
	}
	return c.localAddr
}

func (c *tdsTLSMemoryConn) RemoteAddr() net.Addr {
	if c.remoteAddr == nil {
		c.remoteAddr = tdsTLSTestAddr("remote")
	}
	return c.remoteAddr
}

type tdsTLSTestAddr string

func (a tdsTLSTestAddr) Network() string { return "test" }
func (a tdsTLSTestAddr) String() string  { return string(a) }

func (c *tdsTLSMemoryConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

func (c *tdsTLSMemoryConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *tdsTLSMemoryConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}
