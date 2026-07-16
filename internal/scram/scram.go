// Package scram implements the SCRAM-SHA-256 authentication mechanism
// (RFC 7677, RFC 5802) for PostgreSQL proxy auth mode.
//
// SASL state machine:
//
//	S: Server sends AuthRequest (SCRAM-SHA-256) + server-first-message
//	   server-first-message = r=<nonce>,s=<salt>,i=<iterations>
//	C: Client responds with client-first-message + client-final-message
//	   client-first-message  = n=<user>,r=<client-nonce>
//	   client-final-message  = c=<gs2-header>,r=<combined-nonce>,p=<proof>
//	S: Server validates proof, responds with server-final-message
//	   server-final-message  = v=<server-signature>
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

// NonceLen is the number of random bytes in each nonce (16 bytes = 128 bits).
const NonceLen = 16

// DefaultIterations is the default SCRAM iteration count.
const DefaultIterations = 4096

// SaltLen is the length of the random salt (16 bytes).
const SaltLen = 16

// --- PBKDF2 (zero external dependencies) ---

// pbkdf2 derives a key from a password using the PBKDF2 algorithm (RFC 2898).
// Uses HMAC-SHA256 as the PRF. Only implemented for the parameters needed by SCRAM.
func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	dk := make([]byte, 0, keyLen)

	// DK = T1 || T2 || ... || Tdklen/hlen
	// Ti = HMAC(Password, Salt || INT32(i))
	block := 1
	for len(dk) < keyLen {
		prf.Reset()
		prf.Write(salt)
		// INT32(i) — big-endian 4-byte block index
		prf.Write([]byte{
			byte(block >> 24),
			byte(block >> 16),
			byte(block >> 8),
			byte(block),
		})
		u := prf.Sum(nil)

		// T_i = U_1 XOR U_2 XOR ... XOR U_c
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

// --- SCRAM-SHA-256 primitives ---

// SaltedPassword computes SaltedPassword = PBKDF2(password, salt, iterations, 32).
func SaltedPassword(password string, salt []byte, iterations int) []byte {
	return pbkdf2([]byte(password), salt, iterations, 32)
}

// ClientKey computes ClientKey = HMAC-SHA256(SaltedPassword, "Client Key").
func ClientKey(saltedPassword []byte) []byte {
	mac := hmac.New(sha256.New, saltedPassword)
	mac.Write([]byte("Client Key"))
	return mac.Sum(nil)
}

// StoredKey computes StoredKey = SHA-256(ClientKey).
func StoredKey(clientKey []byte) []byte {
	h := sha256.Sum256(clientKey)
	return h[:]
}

// ServerKey computes ServerKey = HMAC-SHA256(SaltedPassword, "Server Key").
func ServerKey(saltedPassword []byte) []byte {
	mac := hmac.New(sha256.New, saltedPassword)
	mac.Write([]byte("Server Key"))
	return mac.Sum(nil)
}

// ClientSignature computes ClientSignature = HMAC-SHA256(StoredKey, AuthMessage).
func ClientSignature(storedKey, authMessage []byte) []byte {
	mac := hmac.New(sha256.New, storedKey)
	mac.Write(authMessage)
	return mac.Sum(nil)
}

// ClientProof computes ClientProof = ClientKey XOR ClientSignature.
func ClientProof(clientKey, clientSignature []byte) []byte {
	if len(clientKey) != len(clientSignature) {
		panic("scram: ClientKey and ClientSignature length mismatch")
	}
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}
	return proof
}

// ServerSignature computes ServerSignature = HMAC-SHA256(ServerKey, AuthMessage).
func ServerSignature(serverKey, authMessage []byte) []byte {
	mac := hmac.New(sha256.New, serverKey)
	mac.Write(authMessage)
	return mac.Sum(nil)
}

// GenerateNonce generates a random nonce (crypto/rand, base64-encoded).
func GenerateNonce() (string, error) {
	b := make([]byte, NonceLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("scram: generating nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateSalt generates a random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("scram: generating salt: %w", err)
	}
	return salt, nil
}

// --- Message parsing ---

// ServerFirstMessage is the server's initial challenge.
type ServerFirstMessage struct {
	Nonce      string // combined nonce (client nonce + server nonce)
	Salt       []byte
	Iterations int
}

// Marshal encodes the server-first-message as a SCRAM string.
func (m *ServerFirstMessage) Marshal() string {
	return fmt.Sprintf("r=%s,s=%s,i=%d",
		m.Nonce,
		base64.StdEncoding.EncodeToString(m.Salt),
		m.Iterations,
	)
}

// ParseServerFirstMessage parses a server-first-message string.
func ParseServerFirstMessage(msg string) (*ServerFirstMessage, error) {
	sm := &ServerFirstMessage{}
	for _, part := range strings.Split(msg, ",") {
		if len(part) < 2 || part[1] != '=' {
			continue
		}
		key := part[0]
		value := part[2:]
		switch key {
		case 'r':
			sm.Nonce = value
		case 's':
			salt, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("scram: decoding salt: %w", err)
			}
			sm.Salt = salt
		case 'i':
			i, err := strconv.Atoi(value)
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

// ClientFirstMessage holds the parsed client-first-message.
type ClientFirstMessage struct {
	GS2Header string // gs2-cbind-flag + authzid
	Username  string
	Nonce     string // client nonce (bare)
}

// ParseClientFirstMessage parses a client-first-message.
func ParseClientFirstMessage(msg string) (*ClientFirstMessage, error) {
	// Format: gs2-header,n=<user>,r=<nonce>
	// The gs2-header ends with a comma before the bare attributes.
	comma1 := strings.IndexByte(msg, ',')
	if comma1 < 0 {
		return nil, fmt.Errorf("scram: invalid client-first-message: %q", msg)
	}
	gs2Header := msg[:comma1]
	bare := msg[comma1+1:]

	cf := &ClientFirstMessage{GS2Header: gs2Header}
	for _, part := range strings.Split(bare, ",") {
		if len(part) < 2 || part[1] != '=' {
			continue
		}
		val := part[2:]
		switch part[0] {
		case 'n':
			cf.Username = val
		case 'r':
			cf.Nonce = val
		}
	}
	if cf.Nonce == "" {
		return nil, fmt.Errorf("scram: client-first-message missing nonce: %q", msg)
	}
	return cf, nil
}

// ClientFinalMessage holds the parsed client-final-message.
type ClientFinalMessage struct {
	ChannelBinding string // base64-encoded gs2-header
	Nonce          string // combined nonce (must match server's)
	Proof          []byte // client proof
}

// ParseClientFinalMessage parses a client-final-message.
func ParseClientFinalMessage(msg string) (*ClientFinalMessage, error) {
	cf := &ClientFinalMessage{}
	for _, part := range strings.Split(msg, ",") {
		if len(part) < 2 || part[1] != '=' {
			continue
		}
		val := part[2:]
		switch part[0] {
		case 'c':
			cf.ChannelBinding = val
		case 'r':
			cf.Nonce = val
		case 'p':
			proof, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				return nil, fmt.Errorf("scram: decoding proof: %w", err)
			}
			cf.Proof = proof
		}
	}
	if cf.Nonce == "" || len(cf.Proof) == 0 {
		return nil, fmt.Errorf("scram: incomplete client-final-message: %q", msg)
	}
	return cf, nil
}

// ServerFinalMessage encodes the server's final verification.
func ServerFinalMessage(serverSig []byte) string {
	return "v=" + base64.StdEncoding.EncodeToString(serverSig)
}

// AuthMessage builds the auth message used in HMAC computations.
// Format: client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
func AuthMessage(bareClientFirst, serverFirst string) string {
	return bareClientFirst + "," + serverFirst + ","
}

// ClientFirstMessageBare extracts the bare (without gs2) part of the client-first-message.
// The gs2-header in PostgreSQL SCRAM is "n,," (no channel binding, no authzid).
// Format: gs2-cbind-flag "," [authzid ","] "n=" user "," "r=" nonce
// The bare part starts after the second comma.
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

// ClientFinalMessageWithoutProof strips the proof from the client-final-message.
func ClientFinalMessageWithoutProof(msg string) string {
	// Find ",p=" and remove it and everything after
	pIdx := strings.LastIndex(msg, ",p=")
	if pIdx < 0 {
		return msg
	}
	return msg[:pIdx]
}

// --- High-level server API ---

// Server holds the state for the server side of a SCRAM exchange.
type Server struct {
	password        string
	clientFirst     string
	serverFirst     string
	clientFinal     string
	clientNonce     string
	saltedPassword  []byte
	serverFirstMsg  *ServerFirstMessage
}

// NewServer creates a new SCRAM server for the given password (stored credential).
func NewServer(password string) *Server {
	return &Server{password: password}
}

// ServerFirst generates the server-first-message given the client-first-message.
// Returns the server-first-message string to send to the client.
func (s *Server) ServerFirst(clientFirst string) (string, error) {
	s.clientFirst = clientFirst

	cf, err := ParseClientFirstMessage(clientFirst)
	if err != nil {
		return "", fmt.Errorf("scram server: %w", err)
	}
	s.clientNonce = cf.Nonce

	// Generate server nonce and combine
	serverNonce, err := GenerateNonce()
	if err != nil {
		return "", err
	}
	combinedNonce := cf.Nonce + serverNonce

	// Generate salt
	salt, err := GenerateSalt()
	if err != nil {
		return "", err
	}

	s.serverFirstMsg = &ServerFirstMessage{
		Nonce:      combinedNonce,
		Salt:       salt,
		Iterations: DefaultIterations,
	}
	s.serverFirst = s.serverFirstMsg.Marshal()
	return s.serverFirst, nil
}

// ClientFinal validates the client-final-message and returns the server-final-message.
// Returns (serverFinalMessage, nil) on success, or ("", error) on auth failure.
func (s *Server) ClientFinal(clientFinal string) (string, error) {
	s.clientFinal = clientFinal

	cf, err := ParseClientFinalMessage(clientFinal)
	if err != nil {
		return "", fmt.Errorf("scram server: %w", err)
	}

	// Verify nonce
	if cf.Nonce != s.serverFirstMsg.Nonce {
		return "", fmt.Errorf("scram: nonce mismatch")
	}

	// Compute expected proof
	saltedPass := SaltedPassword(s.password, s.serverFirstMsg.Salt, s.serverFirstMsg.Iterations)
	s.saltedPassword = saltedPass

	clientKey := ClientKey(saltedPass)
	storedKey := StoredKey(clientKey)

	bareClientFirst := ClientFirstMessageBare(s.clientFirst)
	clientFinalNoProof := ClientFinalMessageWithoutProof(s.clientFinal)
	authMsg := AuthMessage(bareClientFirst, s.serverFirst)
	authMsg += clientFinalNoProof // append the client-final-message-without-proof

	clientSig := ClientSignature(storedKey, []byte(authMsg))
	expectedProof := ClientProof(clientKey, clientSig)

	// Compare proofs (constant-time)
	if !hmac.Equal(cf.Proof, expectedProof) {
		return "", fmt.Errorf("scram: authentication failed — invalid proof")
	}

	// Compute server signature
	serverKey := ServerKey(saltedPass)
	serverSig := ServerSignature(serverKey, []byte(authMsg))

	return ServerFinalMessage(serverSig), nil
}

// --- High-level client API ---

// ClientFirst generates the client-first-message.
func ClientFirst(username, clientNonce string) string {
	return "n,,n=" + username + ",r=" + clientNonce
}

// ClientFinalProof computes the client-final-message proof value.
func ClientFinalProof(password string, serverFirst *ServerFirstMessage, clientFirst, clientFinalBare string) []byte {
	saltedPass := SaltedPassword(password, serverFirst.Salt, serverFirst.Iterations)
	clientKey := ClientKey(saltedPass)
	storedKey := StoredKey(clientKey)

	bareClientFirst := ClientFirstMessageBare(clientFirst)
	authMsg := AuthMessage(bareClientFirst, serverFirst.Marshal())
	authMsg += clientFinalBare

	clientSig := ClientSignature(storedKey, []byte(authMsg))
	return ClientProof(clientKey, clientSig)
}

// VerifyServerSignature validates the server's final message.
func VerifyServerSignature(password string, serverFirst *ServerFirstMessage, authMessage string, serverFinalMsg string) error {
	saltedPass := SaltedPassword(password, serverFirst.Salt, serverFirst.Iterations)
	serverKey := ServerKey(saltedPass)
	expectedSig := ServerSignature(serverKey, []byte(authMessage))

	// Parse server-final-message: "v=<base64>"
	if !strings.HasPrefix(serverFinalMsg, "v=") {
		return fmt.Errorf("scram: invalid server-final-message: %q", serverFinalMsg)
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
