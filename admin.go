package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var dashboardFiles embed.FS

type ClientHost struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Address string    `json:"address"`
	Local   bool      `json:"local"`
	Last    time.Time `json:"last"`
	Devices []Device  `json:"devices"`
	Ports   []Port    `json:"ports"`
	Policy  Policy    `json:"policy"`
	Removed bool      `json:"removed"`
	Health  string    `json:"health,omitempty"`
}

type hostRecord struct {
	ClientHost
	TokenHash string
}

type adminState struct {
	Salt, Password, Recovery, AuditKey, LocalToken, Bootstrap string
	Hosts                                                     map[string]*hostRecord
}

const maxAuditBytes int64 = 256 << 20
const maxAuditEvents = 10000

type ledgerLine struct {
	Event Event
	Hash  string
}

type ledger struct {
	path       string
	key        []byte
	head       string
	checkpoint string
	events     []Event
	seen       map[string]bool
}

func (l *ledger) hash(e Event, head string) string {
	raw, _ := json.Marshal(e)
	mac := hmac.New(sha256.New, l.key)
	mac.Write([]byte(head))
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

func (l *ledger) remember(e Event) {
	if len(l.events) == maxAuditEvents {
		copy(l.events, l.events[1:])
		l.events[len(l.events)-1] = e
	} else {
		l.events = append(l.events, e)
	}
}

func (l *ledger) files() ([]string, error) {
	files, err := filepath.Glob(l.path + ".archive-*")
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	if _, err := os.Stat(l.path); err == nil {
		files = append(files, l.path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return files, nil
}

func (l *ledger) read() error {
	var anchor string
	if err := load(l.checkpoint, &anchor); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	anchored := anchor == ""
	recovered := false
	files, err := l.files()
	if err != nil {
		return err
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		reader := bufio.NewReaderSize(f, 1<<20)
		var offset int64
		for {
			raw, readErr := reader.ReadSlice('\n')
			if len(raw) == 0 && readErr == io.EOF {
				break
			}
			if readErr != nil && readErr != io.EOF {
				f.Close()
				return readErr
			}
			var line ledgerLine
			valid := json.Unmarshal(raw, &line) == nil && equal(l.hash(line.Event, l.head), line.Hash)
			if !valid {
				// Only an uncommitted final fragment in the active file is repairable.
				// A complete modified record, missing archive, or missing anchor is fatal.
				if path == l.path && readErr == io.EOF && anchored {
					f.Close()
					if err := os.WriteFile(l.path+".partial-"+secret(8), raw, 0600); err != nil {
						return err
					}
					if err := os.Truncate(path, offset); err != nil {
						return err
					}
					recovered = true
					break
				}
				f.Close()
				return errors.New("audit log integrity verification failed")
			}
			l.head = line.Hash
			anchored = anchored || equal(anchor, l.head)
			l.remember(line.Event)
			l.seen[line.Event.ID] = true
			offset += int64(len(raw))
			if readErr == io.EOF {
				f.Close()
				out, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					return err
				}
				_, err = out.Write([]byte{'\n'})
				if err == nil {
					err = out.Sync()
				}
				out.Close()
				if err != nil {
					return err
				}
				break
			}
		}
		f.Close()
	}
	if !anchored {
		return errors.New("audit log was truncated or an archive is missing")
	}
	if err := save(l.checkpoint, l.head); err != nil {
		return err
	}
	if recovered {
		return l.append([]Event{event("audit.gap", "Admin", "Recovered incomplete final audit write; original fragment retained in .partial file")})
	}
	return nil
}

func (l *ledger) append(events []Event) error {
	pending := make([]ledgerLine, 0, len(events))
	head := l.head
	seen := map[string]bool{}
	for _, e := range events {
		if l.seen[e.ID] || seen[e.ID] {
			continue
		}
		head = l.hash(e, head)
		pending = append(pending, ledgerLine{Event: e, Hash: head})
		seen[e.ID] = true
	}
	if len(pending) == 0 {
		return nil
	}
	// Fail explicitly before consuming unlimited disk; retain all prior evidence.
	var batch bytes.Buffer
	encoder := json.NewEncoder(&batch)
	for _, row := range pending {
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	files, err := l.files()
	if err != nil {
		return err
	}
	var total, activeSize int64
	partials, err := filepath.Glob(l.path + ".partial-*")
	if err != nil {
		return err
	}
	files = append(files, partials...)
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		total += info.Size()
		if path == l.path {
			activeSize = info.Size()
		}
	}
	if total+int64(batch.Len()) > maxAuditBytes {
		return errors.New("audit storage limit reached (256 MiB); export and back up the complete audit before maintenance")
	}
	if activeSize > 0 && activeSize+int64(batch.Len()) > 16<<20 {
		archive := l.path + ".archive-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
		if err := os.Rename(l.path, archive); err != nil {
			return err
		}
		activeSize = 0
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := f.Write(batch.Bytes())
	if err == nil && n != batch.Len() {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		return errors.Join(err, f.Truncate(activeSize), f.Sync())
	}
	for _, row := range pending {
		l.head = row.Hash
		l.remember(row.Event)
		l.seen[row.Event.ID] = true
	}

	return save(l.checkpoint, l.head)
}

type admin struct {
	mu          sync.Mutex
	dir         string
	state       adminState
	log         ledger
	pin         string
	sessions    map[string]time.Time
	attempts    int
	nextAttempt time.Time
	candidates  map[string]Candidate
	scanLock    sync.Mutex
	enrollLock  sync.Mutex
}

func newAdmin(dir string) (*admin, error) {
	a := &admin{dir: dir, sessions: map[string]time.Time{}, candidates: map[string]Candidate{}}
	err := load(filepath.Join(dir, "state.json"), &a.state)
	if errors.Is(err, os.ErrNotExist) {
		localID := secret(16)
		a.state = adminState{AuditKey: secret(32), LocalToken: secret(32), Bootstrap: secret(32), Hosts: map[string]*hostRecord{}}
		a.state.Hosts[localID] = &hostRecord{ClientHost: ClientHost{ID: localID, Name: machineName(), Address: "127.0.0.1", Local: true}, TokenHash: fingerprint([]byte(a.state.LocalToken))}
		err = a.persist()
	}
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(a.state.AuditKey)
	if err != nil || len(key) != 32 || a.state.Hosts == nil {
		return nil, errors.New("invalid admin state")
	}
	a.log = ledger{path: filepath.Join(dir, "audit.jsonl"), checkpoint: filepath.Join(dir, "audit-head.json"), key: key, seen: map[string]bool{}}
	if err := a.log.read(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *admin) persist() error { return save(filepath.Join(a.dir, "state.json"), a.state) }

func runAdmin(ctx context.Context, dir string) error {
	a, err := newAdmin(dir)
	if err != nil {
		return err
	}
	cert, err := serverCertificate(dir)
	if err != nil {
		return err
	}
	a.pin = fingerprint(cert.Certificate[0])
	for _, host := range a.state.Hosts {
		if host.Local {
			local := Enrollment{ID: host.ID, Token: a.state.LocalToken, Pin: a.pin, Address: "127.0.0.1:" + tlsPort}
			if err := save(filepath.Join(filepath.Dir(dir), "Agent", "local.json"), local); err != nil {
				return err
			}
			break
		}
	}
	ui, err := net.Listen("tcp4", uiAddress)
	if err != nil {
		return err
	}
	defer ui.Close()
	lan, err := net.Listen("tcp4", ":"+tlsPort)
	if err != nil {
		return err
	}
	defer lan.Close()
	uiServer := httpServer(http.HandlerFunc(a.dashboard))
	defer uiServer.Close()
	api := httpServer(http.HandlerFunc(a.agent))
	api.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	defer api.Close()
	failed := make(chan error, 2)
	go func() { failed <- uiServer.Serve(ui) }()
	go func() { failed <- api.ServeTLS(lan, "", "") }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		return err
	}
}

func (a *admin) agent(w http.ResponseWriter, r *http.Request) {
	if !lanAddress(r.RemoteAddr) || r.Method != "POST" {
		reject(w, 403, "forbidden")
		return
	}
	id, found := strings.CutPrefix(r.URL.Path, "/agent/")
	if !found || !validHex(id, 16) {
		reject(w, 404, "invalid")
		return
	}
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || !validHex(token, 32) {
		reject(w, 401, "forbidden")
		return
	}
	var hb Heartbeat
	if !requestBody(w, r, &hb, 4<<20) {
		return
	}
	if len(hb.Events) > 100 || len(hb.Devices) > 2048 || len(hb.Ports) > 2048 {
		reject(w, 400, "invalid")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	host := a.state.Hosts[id]
	if host == nil || !equal(fingerprint([]byte(token)), host.TokenHash) {
		reject(w, 401, "forbidden")
		return
	}
	if host.Removed {
		if len(hb.Events) == 1 && hb.Events[0].Kind == "agent.removed" && a.log.seen[hb.Events[0].ID] {
			respond(w, 200, host.Policy)
		} else {
			reject(w, 401, "forbidden")
		}
		return
	}
	for i := range hb.Events {
		e := &hb.Events[i]
		if !validHex(e.ID, 16) || len(e.Kind) > 60 || len(e.Item) > 32768 || len(e.Detail) > 32768 || e.Time.IsZero() {
			reject(w, 400, "invalid")
			return
		}
		if e.Kind == "agent.removed" && !host.Policy.Remove {
			reject(w, 403, "forbidden")
			return
		}
		e.Host = host.Name
		e.HostID = host.ID
	}
	if err := a.log.append(hb.Events); err != nil {
		reject(w, 500, "audit_error")
		return
	}
	for _, e := range hb.Events {
		if e.Kind == "agent.removed" {
			host.Removed = true
		}
	}
	host.Devices, host.Ports, host.Health, host.Last = hb.Devices, hb.Ports, hb.Health, time.Now().UTC()
	if err := a.persist(); err != nil {
		reject(w, 500, "service")
		return
	}
	respond(w, 200, host.Policy)
}

func (a *admin) dashboard(w http.ResponseWriter, r *http.Request) {
	if !localRequest(r, uiAddress) {
		reject(w, 403, "forbidden")
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			reject(w, 405, "invalid")
			return
		}
		files, _ := fs.Sub(dashboardFiles, "web")
		w.Header().Set("Cache-Control", "no-cache")
		http.FileServerFS(files).ServeHTTP(w, r)
		return
	}
	if r.Method != "GET" && (r.Method != "POST" || r.Header.Get("Origin") != "http://"+uiAddress || r.Header.Get("X-HubMaster") != "admin") {
		reject(w, 403, "forbidden")
		return
	}
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/auth/") {
		a.auth(w, r)
		return
	}
	a.mu.Lock()
	authenticated := false
	if cookie, err := r.Cookie("hm_session"); err == nil {
		authenticated = time.Now().Before(a.sessions[cookie.Value])
	}
	if r.Method == "GET" && r.URL.Path == "/api/status" {
		respond(w, 200, map[string]any{"setup": a.state.Password == "", "authenticated": authenticated, "version": productVersion})
		a.mu.Unlock()
		return
	}
	if !authenticated {
		a.mu.Unlock()
		reject(w, 401, "login")
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/dashboard":
		hosts := make([]ClientHost, 0, len(a.state.Hosts))
		for _, host := range a.state.Hosts {
			if !host.Removed {
				hosts = append(hosts, host.ClientHost)
			}
		}
		slices.SortFunc(hosts, func(x, y ClientHost) int {
			if x.Local != y.Local {
				if x.Local {
					return -1
				}
				return 1
			}
			return strings.Compare(x.Name, y.Name)
		})
		respond(w, 200, hosts)
		a.mu.Unlock()
	case r.Method == "GET" && r.URL.Path == "/api/audit/export":
		defer a.mu.Unlock()
		files, err := a.log.files()
		if err != nil {
			reject(w, 500, "audit_error")
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", "attachment; filename=hubmaster-audit.jsonl")
		w.Header().Set("Cache-Control", "no-store")
		for _, path := range files {
			f, err := os.Open(path)
			if err != nil {
				return
			}
			_, err = io.Copy(w, f)
			f.Close()
			if err != nil {
				return
			}
		}
	case r.Method == "GET" && r.URL.Path == "/api/audit":
		end := len(a.log.events)
		before, _ := strconv.Atoi(r.URL.Query().Get("before"))
		if before > 0 && before < end {
			end = before
		}
		hostID := r.URL.Query().Get("host")
		var host *hostRecord
		legacyUnique := false
		if hostID != "" {
			host = a.state.Hosts[hostID]
			if host == nil {
				a.mu.Unlock()
				reject(w, 404, "invalid")
				return
			}
			matches := 0
			for _, candidate := range a.state.Hosts {
				if candidate.Name == host.Name {
					matches++
				}
			}
			legacyUnique = matches == 1
		}
		rows := make([]Event, 0, 150)
		cursor := end
		for cursor > 0 && len(rows) < 150 {
			cursor--
			e := a.log.events[cursor]
			if host != nil {
				legacyHost := e.Host == host.Name || e.Kind == "agent.paired" && e.Item == host.Name
				if e.HostID != hostID && !(e.HostID == "" && legacyUnique && legacyHost) {
					continue
				}
			}
			rows = append(rows, e)
		}
		respond(w, 200, map[string]any{"events": rows, "before": cursor, "count": len(a.log.events)})
		a.mu.Unlock()
	case r.Method == "POST" && r.URL.Path == "/api/scan":
		a.mu.Unlock()
		a.scan(w)
	case r.Method == "POST" && r.URL.Path == "/api/pair":
		a.mu.Unlock()
		a.enroll(w, r)
	case r.Method == "POST" && r.URL.Path == "/api/policy":
		a.policy(w, r)
		a.mu.Unlock()
	default:
		a.mu.Unlock()
		reject(w, 404, "invalid")
	}
}

func passHash(salt, password string) string {
	key, err := pbkdf2.Key(sha256.New, password, []byte(salt), 600000, 32)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(key)
}

func (a *admin) auth(w http.ResponseWriter, r *http.Request) {
	var body struct{ Password, Key, CurrentPassword string }
	if !requestBody(w, r, &body, 4096) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	var recovery string
	switch r.URL.Path {
	case "/api/auth/logout":
		if cookie, err := r.Cookie("hm_session"); err == nil {
			delete(a.sessions, cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: "hm_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		respond(w, 200, map[string]bool{"ok": true})
		return
	case "/api/auth/setup", "/api/auth/reset", "/api/auth/login", "/api/auth/change":
	default:
		reject(w, 404, "invalid")
		return
	}
	if now.Before(a.nextAttempt) {
		reject(w, 429, "rate")
		return
	}
	valid := false
	setup := r.URL.Path == "/api/auth/setup"
	reset := r.URL.Path == "/api/auth/reset"
	change := r.URL.Path == "/api/auth/change"
	if change {
		cookie, err := r.Cookie("hm_session")
		if err != nil || !now.Before(a.sessions[cookie.Value]) {
			reject(w, 401, "login")
			return
		}
	}
	if setup || reset || change {
		if !strongPassword(body.Password) {
			reject(w, 400, "password_length")
			return
		}
		key := strings.ToLower(strings.TrimSpace(body.Key))
		valid = (setup && a.state.Password == "" && a.state.Bootstrap != "" && equal(key, a.state.Bootstrap)) ||
			(reset && a.state.Recovery != "" && equal(fingerprint([]byte(key)), a.state.Recovery)) ||
			(change && a.state.Password != "" && len(body.CurrentPassword) <= 256 && equal(passHash(a.state.Salt, body.CurrentPassword), a.state.Password))
		if valid {
			salt := secret(16)
			recovery = secret(24)
			previous := a.state
			a.state.Salt, a.state.Password, a.state.Recovery, a.state.Bootstrap = salt, passHash(salt, body.Password), fingerprint([]byte(recovery)), ""
			if err := a.persist(); err != nil {
				a.state = previous
				reject(w, 500, "service")
				return
			}
			clear(a.sessions)
			action := "password.setup"
			if reset {
				action = "password.reset"
			}
			if change {
				action = "password.changed"
			}
			if err := a.log.append([]Event{event(action, "Admin", "")}); err != nil {
				// Credential change succeeded; do not hide the recovery key on an audit failure.
				log.Print("credential audit: ", err)
			}
		}
	} else if a.state.Password != "" && len(body.Password) <= 256 {
		valid = equal(passHash(a.state.Salt, body.Password), a.state.Password)
	}
	if !valid {
		a.attempts++
		a.nextAttempt = now.Add(time.Duration(min(a.attempts, 15)) * time.Second)
		reject(w, 401, "credentials")
		return
	}
	a.attempts = 0
	a.nextAttempt = time.Time{}
	for session, expires := range a.sessions {
		if !now.Before(expires) {
			delete(a.sessions, session)
		}
	}
	session := secret(32)
	a.sessions[session] = now.Add(8 * time.Hour)
	http.SetCookie(w, &http.Cookie{Name: "hm_session", Value: session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	respond(w, 200, map[string]string{"recovery": recovery})
}

func (a *admin) scan(w http.ResponseWriter) {
	if !a.scanLock.TryLock() {
		reject(w, 429, "rate")
		return
	}
	defer a.scanLock.Unlock()
	candidates, err := scanLAN()
	if err != nil {
		reject(w, 503, "scan_error")
		return
	}
	a.mu.Lock()
	clear(a.candidates)
	for _, c := range candidates {
		a.candidates[c.ID] = c
	}
	a.mu.Unlock()
	respond(w, 200, candidates)
}

func (a *admin) enroll(w http.ResponseWriter, r *http.Request) {
	if !a.enrollLock.TryLock() {
		reject(w, 429, "rate")
		return
	}
	defer a.enrollLock.Unlock()
	var body struct{ ID, OTP string }
	if !requestBody(w, r, &body, 2048) {
		return
	}
	a.mu.Lock()
	c, ok := a.candidates[body.ID]
	a.mu.Unlock()
	if !ok || !validOTP(body.OTP) || time.Now().After(c.Expires) {
		reject(w, 400, "otp")
		return
	}
	s := makeSPAKE(body.OTP, c.ID, false)
	client := safeClient(&http.Transport{})
	url := "http://" + net.JoinHostPort(c.IP, pairPort)
	var reply pairReply
	if err := post(client, url+"/pair/start", "", pairStart{ID: c.ID, Public: s.public}, &reply); err != nil {
		reject(w, 400, "otp")
		return
	}
	key, proof, expected, err := s.derive(reply.Public, c.ID)
	if err != nil || !hmac.Equal(reply.Proof, expected) || !validHex(reply.Session, 16) {
		reject(w, 400, "otp")
		return
	}
	e := Enrollment{ID: secret(16), Token: secret(32), Pin: a.pin}
	payload, err := sealPair(key, c.ID, e)
	if err != nil {
		reject(w, 500, "service")
		return
	}
	a.mu.Lock()
	a.state.Hosts[e.ID] = &hostRecord{ClientHost: ClientHost{ID: e.ID, Name: c.Name, Address: c.IP}, TokenHash: fingerprint([]byte(e.Token))}
	err = a.persist()
	if err != nil {
		delete(a.state.Hosts, e.ID)
	}
	a.mu.Unlock()
	if err != nil {
		reject(w, 500, "service")
		return
	}
	var result map[string]bool
	if err := post(client, url+"/pair/finish", "", pairFinish{Session: reply.Session, Proof: proof, Payload: payload}, &result); err != nil || !result["ok"] {
		reject(w, 503, "pair_pending")
		return
	}
	a.mu.Lock()
	delete(a.candidates, c.ID)
	paired := event("agent.paired", c.Name, c.IP)
	paired.Host, paired.HostID = c.Name, e.ID
	_ = a.log.append([]Event{paired})
	a.mu.Unlock()
	respond(w, 200, map[string]string{"id": e.ID})
}

func (a *admin) policy(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID, Device, Action string }
	if !requestBody(w, r, &body, 16<<10) {
		return
	}
	host := a.state.Hosts[body.ID]
	if host == nil || host.Removed || host.Policy.Remove {
		reject(w, 404, "invalid")
		return
	}
	next := host.Policy
	switch body.Action {
	case "allow", "block":
		found := false
		for _, dev := range host.Devices {
			if dev.ID == body.Device && dev.Controllable {
				found = true
				break
			}
		}
		if !found {
			reject(w, 400, "invalid")
			return
		}
		if _, exists := host.Policy.Devices[body.Device]; !exists && len(host.Policy.Devices) >= 4096 {
			reject(w, 400, "policy_limit")
			return
		}
		next.Devices = map[string]string{}
		for id, rule := range host.Policy.Devices {
			next.Devices[id] = rule
		}
		next.Devices[body.Device] = body.Action
	case "hid_on", "hid_off":
		next.ProtectHID = body.Action == "hid_on"
	case "remove":
		if host.Local {
			reject(w, 400, "invalid")
			return
		}
		next.Remove = true
	default:
		reject(w, 400, "invalid")
		return
	}
	e := event("policy."+body.Action, body.Device, "")
	e.Host = host.Name
	e.HostID = host.ID
	if err := a.log.append([]Event{e}); err != nil {
		reject(w, 500, "audit_error")
		return
	}
	previous := host.Policy
	host.Policy = next
	if err := a.persist(); err != nil {
		host.Policy = previous
		reject(w, 500, "service")
		return
	}
	respond(w, 200, next)
}

// Called only by the elevated desktop recovery command while the service is stopped.
func (a *admin) authorizeLocalRecovery() error {
	previous := a.state
	if err := a.log.append([]Event{event("password.recovery_authorized", "Admin", "Windows administrator authorized local recovery")}); err != nil {
		return err
	}
	a.state.Password, a.state.Salt, a.state.Recovery = "", "", ""
	a.state.Bootstrap = secret(32)
	if err := a.persist(); err != nil {
		a.state = previous
		return err
	}
	clear(a.sessions)
	return nil
}
