// Package scram implements SCRAM-SHA-256 (RFC 7677, RFC 5802) for PostgreSQL proxy auth.
package scram

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	NonceLen          = 16
	DefaultIterations = 4096
	SaltLen           = 16
)

func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	dk := make([]byte, 0, keyLen)
	block := 1
	for len(dk) < keyLen {
		prf.Reset()
		prf.Write(salt)
		prf.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := prf.Sum(nil)
		t := make([]byte, hashLen)
		copy(t, u)
		for i := 2; i <= iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := 0; j < hashLen; j++ {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
		block++
	}
	return dk[:keyLen]
}

func SaltedPassword(password string, salt []byte, iter int) []byte {
	return pbkdf2([]byte(password), salt, iter, 32)
}

func ClientKey(sp []byte) []byte {
	m := hmac.New(sha256.New, sp)
	m.Write([]byte("Client Key"))
	return m.Sum(nil)
}

func StoredKey(ck []byte) []byte {
	h := sha256.Sum256(ck)
	return h[:]
}

func ServerKey(sp []byte) []byte {
	m := hmac.New(sha256.New, sp)
	m.Write([]byte("Server Key"))
	return m.Sum(nil)
}

func ClientSignature(sk, am []byte) []byte {
	m := hmac.New(sha256.New, sk)
	m.Write(am)
	return m.Sum(nil)
}

func ClientProof(ck, cs []byte) []byte {
	p := make([]byte, len(ck))
	for i := range ck {
		p[i] = ck[i] ^ cs[i]
	}
	return p
}

func ServerSignature(svk, am []byte) []byte {
	m := hmac.New(sha256.New, svk)
	m.Write(am)
	return m.Sum(nil)
}

func GenerateNonce() (string, error) {
	b := make([]byte, NonceLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func GenerateSalt() ([]byte, error) {
	s := make([]byte, SaltLen)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	return s, nil
}

type SFMsg struct {
	Nonce string
	Salt  []byte
	Iter  int
}

func (m *SFMsg) String() string {
	return fmt.Sprintf("r=%s,s=%s,i=%d", m.Nonce, base64.StdEncoding.EncodeToString(m.Salt), m.Iter)
}

func ParseSFMsg(msg string) (*SFMsg, error) {
	sm := &SFMsg{}
	for _, p := range strings.Split(msg, ",") {
		if len(p) < 2 || p[1] != '=' {
			continue
		}
		switch p[0] {
		case 'r':
			sm.Nonce = p[2:]
		case 's':
			s, err := base64.StdEncoding.DecodeString(p[2:])
			if err != nil {
				return nil, fmt.Errorf("salt: %w", err)
			}
			sm.Salt = s
		case 'i':
			i, err := strconv.Atoi(p[2:])
			if err != nil {
				return nil, fmt.Errorf("iter: %w", err)
			}
			sm.Iter = i
		}
	}
	if sm.Nonce == "" || len(sm.Salt) == 0 || sm.Iter == 0 {
		return nil, fmt.Errorf("incomplete: %q", msg)
	}
	return sm, nil
}

func CFBare(msg string) string {
	f := strings.IndexByte(msg, ',')
	if f < 0 {
		return msg
	}
	s := strings.IndexByte(msg[f+1:], ',')
	if s < 0 {
		return msg[f+1:]
	}
	return msg[f+s+2:]
}

func CFNoProof(msg string) string {
	i := strings.LastIndex(msg, ",p=")
	if i < 0 {
		return msg
	}
	return msg[:i]
}

func AuthMsg(bcf, sf string) string {
	return bcf + "," + sf + ","
}

type Server struct {
	pw       string
	cf       string
	sf       string
	sfmsg    *SFMsg
}

func NewServer(pw string) *Server {
	return &Server{pw: pw}
}

func (s *Server) ServerFirst(cf string) (string, error) {
	s.cf = cf
	nc := ""
	for _, p := range strings.Split(cf, ",") {
		if strings.HasPrefix(p, "r=") {
			nc = p[2:]
		}
	}
	if nc == "" {
		return "", fmt.Errorf("missing nonce")
	}
	sn, err := GenerateNonce()
	if err != nil {
		return "", err
	}
	sl, err := GenerateSalt()
	if err != nil {
		return "", err
	}
	s.sfmsg = &SFMsg{Nonce: nc + sn, Salt: sl, Iter: DefaultIterations}
	s.sf = s.sfmsg.String()
	return s.sf, nil
}

func (s *Server) ClientFinal(cf string) (string, error) {
	var nc string
	var pf []byte
	for _, p := range strings.Split(cf, ",") {
		if strings.HasPrefix(p, "r=") {
			nc = p[2:]
		} else if strings.HasPrefix(p, "p=") {
			v, err := base64.StdEncoding.DecodeString(p[2:])
			if err != nil {
				return "", fmt.Errorf("proof: %w", err)
			}
			pf = v
		}
	}
	if nc == "" || len(pf) == 0 {
		return "", fmt.Errorf("incomplete")
	}
	if nc != s.sfmsg.Nonce {
		return "", fmt.Errorf("nonce mismatch")
	}
	sp := SaltedPassword(s.pw, s.sfmsg.Salt, s.sfmsg.Iter)
	ck := ClientKey(sp)
	sk := StoredKey(ck)
	bcf := CFBare(s.cf)
	cnp := CFNoProof(cf)
	am := AuthMsg(bcf, s.sf) + cnp
	cs := ClientSignature(sk, []byte(am))
	ep := ClientProof(ck, cs)
	if !hmac.Equal(pf, ep) {
		return "", fmt.Errorf("auth failed")
	}
	svk := ServerKey(sp)
	ss := ServerSignature(svk, []byte(am))
	return "v=" + base64.StdEncoding.EncodeToString(ss), nil
}

func ClientFirst(user, nc string) string {
	return "n,,n=" + user + ",r=" + nc
}

func ClientFinalProof(pw string, sf *SFMsg, cf, cb string) []byte {
	sp := SaltedPassword(pw, sf.Salt, sf.Iter)
	ck := ClientKey(sp)
	sk := StoredKey(ck)
	bcf := CFBare(cf)
	am := AuthMsg(bcf, sf.String()) + cb
	cs := ClientSignature(sk, []byte(am))
	return ClientProof(ck, cs)
}

func VerifySig(pw string, sf *SFMsg, am, sfm string) error {
	sp := SaltedPassword(pw, sf.Salt, sf.Iter)
	svk := ServerKey(sp)
	es := ServerSignature(svk, []byte(am))
	if !strings.HasPrefix(sfm, "v=") {
		return fmt.Errorf("invalid")
	}
	gs, err := base64.StdEncoding.DecodeString(sfm[2:])
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !hmac.Equal(es, gs) {
		return fmt.Errorf("mismatch")
	}
	return nil
}
