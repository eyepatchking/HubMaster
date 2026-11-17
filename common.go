package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	adminService = "HubMasterAdminV2"
	agentService = "HubMasterAgentV2"
	uiAddress    = "127.0.0.1:47345"
	otpAddress   = "127.0.0.1:47349"
	tlsPort      = "47346"
	scanPort     = "47347"
	pairPort     = "47348"
)

type Device struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Port         string `json:"port"`
	Serial       string `json:"serial,omitempty"`
	Hardware     string `json:"hardware,omitempty"`
	Identity     string `json:"identity"`
	Blocked      bool   `json:"blocked"`
	Present      bool   `json:"present"`
	Controllable bool   `json:"controllable"`
	Risky        bool   `json:"risky"`
}

type attachedDevice struct {
	Device
	Instance string
}

func strongPassword(password string) bool {
	if len(password) < 12 || len(password) > 128 {
		return false
	}
	var lower, upper, digit, symbol bool
	seen := map[rune]bool{}
	for _, c := range password {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		case c >= 33 && c <= 126:
			symbol = true
		default:
			return false
		}
		seen[c] = true
	}
	if !lower || !upper || !digit || !symbol || len(seen) < 5 {
		return false
	}
	value := strings.ToLower(password)
	for i := 0; i+3 <= len(value); i++ {
		segment := value[i : i+3]
		for _, sequence := range []string{"abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba", "01234567890", "09876543210", "qwertyuiop", "poiuytrewq", "asdfghjkl", "lkjhgfdsa", "zxcvbnm", "mnbvcxz"} {
			if strings.Contains(sequence, segment) {
				return false
			}
		}
	}
	for _, word := range []string{"pass", "admin", "root", "user", "test", "love"} {
		if strings.Contains(value, word) {
			return false
		}
	}
	return true
}

type Port struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Connected bool   `json:"connected"`
}

type Event struct {
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	Host   string    `json:"host,omitempty"`
	Kind   string    `json:"kind"`
	Item   string    `json:"item,omitempty"`
	Detail string    `json:"detail,omitempty"`
	HostID string    `json:"host_id,omitempty"`
}

type Policy struct {
	Devices    map[string]string `json:"devices"`
	ProtectHID bool              `json:"protect_hid"`
	Remove     bool              `json:"remove"`
}

type Heartbeat struct {
	Devices []Device `json:"devices"`
	Ports   []Port   `json:"ports"`
	Events  []Event  `json:"events"`
	Health  string   `json:"health,omitempty"`
}

type Enrollment struct {
	ID      string
	Token   string
	Address string
	Pin     string
}

func machineName() string {
	name, _ := os.Hostname()
	return name
}

func dataPath(role string) string {
	return filepath.Join(os.Getenv("ProgramData"), "HubMasterV2", role)
}

func secret(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func load(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(out)
}

func save(path string, value any) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(value)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return replaceFile(f.Name(), path)
}

func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func reject(w http.ResponseWriter, code int, message string) {
	respond(w, code, map[string]string{"error": message})
}

func requestBody(w http.ResponseWriter, r *http.Request, out any, limit int64) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		reject(w, 415, "invalid")
		return false
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		reject(w, 400, "invalid")
		return false
	}
	return true
}

func post(client *http.Client, url, token string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
}

func httpServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 4 * time.Second, ReadTimeout: 9 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 25 * time.Second, MaxHeaderBytes: 16 << 10}
}

func safeClient(transport *http.Transport) *http.Client {
	return &http.Client{Timeout: 6 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func event(kind, item, detail string) Event {
	return Event{ID: secret(16), Time: time.Now().UTC(), Kind: kind, Item: item, Detail: detail}
}

func localRequest(r *http.Request, address string) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	return err == nil && net.ParseIP(host).IsLoopback() && r.Host == address &&
		(r.Header.Get("Origin") == "" || r.Header.Get("Origin") == "http://"+address)
}
