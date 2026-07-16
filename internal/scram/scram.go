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

// --- PBKDF2 ---

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

func SaltedPassword(password string, salt []byte, iterations int) []byte {
	return pbkdf2([]byte(password), salt, iterations, 32)
}

func ClientKey(saltedPassword []byte) []byte {
	mac := hmac.New(sha256.New, saltedPassword)
	mac.Write([]byte("Client Key"))
	return mac.Sum(nil)
}

func StoredKey(clientKey []byte) []byte {
	h := sha256.Sum256(clientKey)
	return h[:]
}

func ServerKey(saltedPassword []byte) []byte {
	mac := hmac.New(sha256.New, saltedPassword)
	mac.Write([]byte("Server Key"))
	return mac.Sum(nil)
}

func ClientSignature(storedKey, authMessage []byte) []byte {
	mac := hmac.New(sha256.New, storedKey)
	mac.Write(authMessage)
	return mac.Sum(nil)
}

func ClientProof(clientKey, clientSignature []byte) []byte {
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}
	return proof
}

func ServerSignature(serverKey, authMessage []byte) []byte {
	mac := hmac.New(sha256.New, serverKey)
	mac.Write(authMessage)
	return mac.Sum(nil)
}

func GenerateNonce() (string, error) {
	b := make([]byte, NonceLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("scram: generating nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("scram: generating salt: %w", err)
	}
	return salt, nil
}

type ServerFirstMessage struct {
	Nonce      string
	Salt       []byte
	Iterations int
}

func (m *ServerFirstMessage) Marshal() string {
	return fmt.Sprintf("r=%s,s=%s,i=%d", m.Nonce, base64.StdEncoding.EncodeToString(m.Salt), m.Iterations)
}

func ParseServerFirstMessage(msg string) (*ServerFirstMessage, error) {
	sm := &ServerFirstMessage{}
	for _, part := range strings.Split(msg, ",") {
		if len(part) < 2 || part[1] != '=' {
			continue
		}
		switch part[0] {
		case 'r':
			sm.Nonce = part[2:]
		case 's':
			salt, err := base64.StdEncoding.DecodeString(part[2:])
			if err != nil {
				return nil, fmt.Errorf("scram: decoding salt: %w", err)
			}
			sm.Salt = salt
		case 'i':
			i, err := strconv.Atoi(part[2:])
			if err != nil {
				return nil, fmt.Errorf("scram: parsing iterations: %w", err)
			}
			sm.Iterations = i
		}
	}
	if sm.Nonce == "" || len(sm.Salt) == 0 || sm.Iterations == 0 {
		return nil, fmt.Errorf("scram: incomplete server-first-message: %q", msg)
	}
	return sm, nil
}

func ClientFirstMessageBare(msg string) string {
	first := strings.IndexByte(msg, ',')
	if first < 0 {
		return msg
	}
	second := strings.IndexByte(msg[first+1:], ',')
	if second < 0 {
		return msg[first+1:]
	}
	return msg[first+second+2:]
}

func ClientFinalMessageWithoutProof(msg string) string {
	pIdx := strings.LastIndex(msg, ",p=")
	if pIdx < 0 {
		return msg
	}
	return msg[:pIdx]
}

func AuthMessage(bareClientFirst, serverFirst string) string {
	return bareClientFirst + "," + serverFirst + ","
}

type Server struct {
	password       string
	clientFirst    string
	serverFirst    string
	clientFinal    string
	clientNonce    string
	saltedPassword []byte
	serverFirstMsg *ServerFirstMessage
}

func NewServer(password string) *Server {
	return &Server{password: password}
}

func (s *Server) ServerFirst(clientFirst string) (string, error) {
	s.clientFirst = clientFirst
	cf := &struct{ Nonce string }{}
	for _, part := range strings.Split(clientFirst, ",") {
		if strings.HasPrefix(part, "r=") {
			cf.Nonce = part[2:]
		}
	}
	if cf.Nonce == "" {
		return "", fmt.Errorf("scram: client-first missing nonce")
	}
	s.clientNonce = cf.Nonce

	serverNonce, err := GenerateNonce()
	if err != nil {
		return "", err
	}
	salt, err := GenerateSalt()
	if err != nil {
		return "", err
	}
	s.serverFirstMsg = &ServerFirstMessage{
		Nonce:      cf.Nonce + serverNonce,
		Salt:       salt,
		Iterations: DefaultIterations,
	}
	s.serverFirst = s.serverFirstMsg.Marshal()
	return s.serverFirst, nil
}

func (s *Server) ClientFinal(clientFinal string) (string, error) {
	s.clientFinal = clientFinal

	cf := &struct {
		Nonce string
		Proof []byte
	}{}
	for _, part := range strings.Split(clientFinal, ",") {
		if strings.HasPrefix(part, "r=") {
			cf.Nonce = part[2:]
		} else if strings.HasPrefix(part, "p=") {
			p, err := base64.StdEncoding.DecodeString(part[2:])
			if err != nil {
				return "", fmt.Errorf("scram: decoding proof: %w", err)
			}
			cf.Proof = p
		}
	}
	if cf.Nonce == "" || len(cf.Proof) == 0 {
		return "", fmt.Errorf("scram: incomplete client-final-message")
	}
	if cf.Nonce != s.serverFirstMsg.Nonce {
		return "", fmt.Errorf("scram: nonce mismatch")
	}

	saltedPass := SaltedPassword(s.password, s.serverFirstMsg.Salt, s.serverFirstMsg.Iterations)
	s.saltedPassword = saltedPass
	clientKey := ClientKey(saltedPass)
	storedKey := StoredKey(clientKey)

	bareClientFirst := ClientFirstMessageBare(s.clientFirst)
	clientFinalNoProof := ClientFinalMessageWithoutProof(s.clientFinal)
	authMsg := AuthMessage(bareClientFirst, s.serverFirst) + clientFinalNoProof

	clientSig := ClientSignature(storedKey, []byte(authMsg))
	expectedProof := ClientProof(clientKey, clientSig)

	if !hmac.Equal(cf.Proof, expectedProof) {
		return "", fmt.Errorf("scram: authentication failed")
	}

	serverKey := ServerKey(saltedPass)
	serverSig := ServerSignature(serverKey, []byte(authMsg))
	return "v=" + base64.StdEncoding.EncodeToString(serverSig), nil
}

func ClientFirst(username, clientNonce string) string {
	return "n,,n=" + username + ",r=" + clientNonce
}

func ClientFinalProof(password string, serverFirst *ServerFirstMessage, clientFirst, clientFinalBare string) []byte {
	saltedPass := SaltedPassword(password, serverFirst.Salt, serverFirst.Iterations)
	clientKey := ClientKey(saltedPass)
	storedKey := StoredKey(clientKey)
	bareClientFirst := ClientFirstMessageBare(clientFirst)
	authMsg := AuthMessage(bareClientFirst, serverFirst.Marshal()) + clientFinalBare
	clientSig := ClientSignature(storedKey, []byte(authMsg))
	return ClientProof(clientKey, clientSig)
}

func VerifyServerSignature(password string, serverFirst *ServerFirstMessage, authMessage string, serverFinalMsg string) error {
	saltedPass := SaltedPassword(password, serverFirst.Salt, serverFirst.Iterations)
	serverKey := ServerKey(saltedPass)
	expectedSig := ServerSignature(serverKey, []byte(authMessage))
	if !strings.HasPrefix(serverFinalMsg, "v=") {
		return fmt.Errorf("scram: invalid server-final-message")
	}
	gotSig, err := base64.StdEncoding.DecodeString(serverFinalMsg[2:])
	if err != nil {
		return fmt.Errorf("scram: decoding server signature: %w", err)
	}
	if !hmac.Equal(expectedSig, gotSig) {
		return fmt.Errorf("scram: server signature mismatch")
	}
	return nil
}
