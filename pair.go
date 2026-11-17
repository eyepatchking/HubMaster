package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const discovery = "HubMaster/2 scan"

type Candidate struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"`
}

func scanLAN() ([]Candidate, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := enableBroadcast(conn); err != nil {
		return nil, err
	}
	targets := []net.IP{net.IPv4bcast}
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok || len(network.Mask) != 4 || network.IP.To4() == nil || network.IP.IsLoopback() {
			continue
		}
		ip := append(net.IP(nil), network.IP.To4()...)
		for i, mask := range network.Mask {
			ip[i] |= ^mask
		}
		targets = append(targets, ip)
	}
	for _, ip := range targets {
		_, _ = conn.WriteToUDP([]byte(discovery), &net.UDPAddr{IP: ip, Port: 47347})
	}
	conn.SetReadDeadline(time.Now().Add(1600 * time.Millisecond))
	result := []Candidate{}
	seen := map[string]bool{}
	var buffer [1536]byte
	for len(result) < 128 {
		n, addr, err := conn.ReadFromUDP(buffer[:])
		if err != nil {
			break
		}
		var c Candidate
		if json.Unmarshal(buffer[:n], &c) != nil || !validHex(c.ID, 16) || len(c.Name) == 0 || len(c.Name) > 128 || !time.Now().Before(c.Expires) {
			continue
		}
		c.IP = addr.IP.String()
		if !seen[c.ID] {
			seen[c.ID] = true
			result = append(result, c)
		}
	}
	return result, nil
}

func validHex(s string, n int) bool {
	if len(s) != 2*n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validOTP(otp string) bool {
	if len(otp) != 6 {
		return false
	}
	for _, c := range otp {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// RFC 9382 SPAKE2-P256-SHA256-HKDF-HMAC. The agent is party B.
var spakeCurve = elliptic.P256()

const pointM = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
const pointN = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

type spake struct {
	w, private, public []byte
	agent              bool
}

func makeSPAKE(otp, id string, agent bool) spake {
	seed := sha256.Sum256([]byte("HubMaster v2 SPAKE2/" + id + "/" + otp))
	w := new(big.Int).SetBytes(seed[:])
	w.Mod(w, new(big.Int).Sub(spakeCurve.Params().N, big.NewInt(1)))
	w.Add(w, big.NewInt(1))
	private, x, y, err := elliptic.GenerateKey(spakeCurve, rand.Reader)
	if err != nil {
		panic(err)
	}
	p := pointM
	if agent {
		p = pointN
	}
	maskX, maskY := maskPoint(p, w.Bytes())
	x, y = spakeCurve.Add(x, y, maskX, maskY)
	if x.Sign() == 0 && y.Sign() == 0 {
		return makeSPAKE(otp, id, agent)
	}
	return spake{w: w.FillBytes(make([]byte, 32)), private: private, public: elliptic.Marshal(spakeCurve, x, y), agent: agent}
}

func maskPoint(point string, scalar []byte) (*big.Int, *big.Int) {
	b, _ := hex.DecodeString(point)
	x, y := elliptic.UnmarshalCompressed(spakeCurve, b)
	return spakeCurve.ScalarMult(x, y, scalar)
}

func (s spake) derive(peer []byte, id string) (key, proofA, proofB []byte, err error) {
	px, py := elliptic.Unmarshal(spakeCurve, peer)
	if px == nil {
		return nil, nil, nil, errors.New("invalid SPAKE2 point")
	}
	p, a, b := pointN, s.public, peer
	if s.agent {
		p, a, b = pointM, peer, s.public
	}
	x, y := maskPoint(p, s.w)
	y.Sub(spakeCurve.Params().P, y)
	px, py = spakeCurve.Add(px, py, x, y)
	if px.Sign() == 0 && py.Sign() == 0 {
		return nil, nil, nil, errors.New("invalid SPAKE2 result")
	}
	x, y = spakeCurve.ScalarMult(px, py, s.private)
	var transcript bytes.Buffer
	for _, value := range [][]byte{[]byte("HubMaster admin v2"), []byte(id), a, b, elliptic.Marshal(spakeCurve, x, y), s.w} {
		transcript.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(value))))
		transcript.Write(value)
	}
	sum := sha256.Sum256(transcript.Bytes())
	confirm, err := hkdf.Key(sha256.New, sum[16:], nil, "ConfirmationKeys", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	macA := hmac.New(sha256.New, confirm[:16])
	macA.Write(b)
	macB := hmac.New(sha256.New, confirm[16:])
	macB.Write(a)
	return sum[:16], macA.Sum(nil), macB.Sum(nil), nil
}

type pairStart struct {
	ID     string
	Public []byte
}
type pairReply struct {
	Session       string
	Public, Proof []byte
}
type pairFinish struct {
	Session        string
	Proof, Payload []byte
}

func sealPair(key []byte, id string, enrollment Enrollment) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(enrollment)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, raw, []byte(id)), nil
}

func openPair(key []byte, id string, encrypted []byte) (Enrollment, error) {
	var data Enrollment
	block, err := aes.NewCipher(key)
	if err != nil {
		return data, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return data, err
	}
	raw, err := aead.Open(nil, nil, encrypted, []byte(id))
	if err != nil {
		return data, err
	}
	err = json.Unmarshal(raw, &data)
	if err == nil && (!validHex(data.ID, 16) || !validHex(data.Token, 32) || !validHex(data.Pin, 32)) {
		err = errors.New("invalid enrollment")
	}
	return data, err
}

type exchange struct {
	key, proof []byte
	deadline   time.Time
	address    string
}
type pairing struct {
	mu        sync.Mutex
	otp       string
	candidate Candidate
	remaining int
	sessions  map[string]exchange
	path      string
	enrolled  bool
}

func (p *pairing) local(w http.ResponseWriter, r *http.Request) {
	if localRequest(r, otpAddress) && r.Method == "GET" && r.URL.Path == "/health" {
		respond(w, 200, map[string]string{"version": productVersion})
		return
	}
	if !localRequest(r, otpAddress) || r.Method != "POST" || r.URL.Path != "/otp" || r.Header.Get("X-HubMaster") != "agent" {
		reject(w, 403, "forbidden")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enrolled {
		reject(w, 409, "enrolled")
		return
	}
	if !time.Now().Before(p.candidate.Expires) {
		n, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			reject(w, 500, "service")
			return
		}
		p.otp = fmt.Sprintf("%06d", n.Int64())
		p.candidate = Candidate{ID: secret(16), Name: machineName(), Expires: time.Now().Add(3 * time.Minute)}
		p.remaining = 5
		p.sessions = map[string]exchange{}
	}
	if p.remaining == 0 {
		reject(w, 429, "wait")
		return
	}
	respond(w, 200, map[string]any{"otp": p.otp, "expires": p.candidate.Expires})
}

func (p *pairing) discover(conn *net.UDPConn) {
	var b [128]byte
	for {
		n, addr, err := conn.ReadFromUDP(b[:])
		if err != nil {
			return
		}
		if string(b[:n]) != discovery {
			continue
		}
		p.mu.Lock()
		candidate := p.candidate
		active := !p.enrolled && p.remaining > 0 && time.Now().Before(candidate.Expires)
		p.mu.Unlock()
		if active {
			raw, _ := json.Marshal(candidate)
			_, _ = conn.WriteToUDP(raw, addr)
		}
	}
}

func (p *pairing) start(w http.ResponseWriter, r *http.Request) {
	var body pairStart
	if !requestBody(w, r, &body, 2048) {
		return
	}
	address, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		reject(w, 400, "invalid")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enrolled || p.remaining <= 0 || !time.Now().Before(p.candidate.Expires) || body.ID != p.candidate.ID {
		reject(w, 403, "otp")
		return
	}
	p.remaining--
	s := makeSPAKE(p.otp, body.ID, true)
	key, a, b, err := s.derive(body.Public, body.ID)
	if err != nil {
		reject(w, 400, "otp")
		return
	}
	id := secret(16)
	p.sessions[id] = exchange{key: key, proof: a, address: address, deadline: time.Now().Add(12 * time.Second)}
	respond(w, 200, pairReply{Session: id, Public: s.public, Proof: b})
}

func (p *pairing) finish(w http.ResponseWriter, r *http.Request) {
	var body pairFinish
	if !requestBody(w, r, &body, 4096) {
		return
	}
	address, _, _ := net.SplitHostPort(r.RemoteAddr)
	p.mu.Lock()
	defer p.mu.Unlock()
	s, found := p.sessions[body.Session]
	if p.enrolled || !found || s.address != address || time.Now().After(s.deadline) || time.Now().After(p.candidate.Expires) || !hmac.Equal(body.Proof, s.proof) {
		reject(w, 403, "otp")
		return
	}
	delete(p.sessions, body.Session)
	data, err := openPair(s.key, p.candidate.ID, body.Payload)
	if err != nil {
		reject(w, 403, "otp")
		return
	}
	data.Address = net.JoinHostPort(address, tlsPort)
	if err := save(p.path, data); err != nil {
		reject(w, 500, "service")
		return
	}
	p.enrolled, p.otp, p.sessions = true, "", nil
	respond(w, 200, map[string]bool{"ok": true})
}

type certFile struct{ DER, Key []byte }

func serverCertificate(dir string) (tls.Certificate, error) {
	var c certFile
	path := filepath.Join(dir, "tls.json")
	if err := load(path, &c); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return tls.Certificate{}, err
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return tls.Certificate{}, err
		}
		now := time.Now()
		t := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "HubMaster LAN"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(8, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		c.DER, err = x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
		if err != nil {
			return tls.Certificate{}, err
		}
		c.Key, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := save(path, c); err != nil {
			return tls.Certificate{}, err
		}
	}
	key, err := x509.ParseECPrivateKey(c.Key)
	return tls.Certificate{Certificate: [][]byte{c.DER}, PrivateKey: key}, err
}

func pinnedClient(pin string) *http.Client {
	return safeClient(&http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 {
			return errors.New("missing HubMaster certificate")
		}
		c := cs.PeerCertificates[0]
		now := time.Now()
		if !equal(fingerprint(c.Raw), pin) || now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return errors.New("HubMaster certificate rejected")
		}
		return nil
	}}})
}

func lanAddress(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	ip := net.ParseIP(strings.TrimSpace(host))
	return err == nil && ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}
