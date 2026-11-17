package main

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hit(t *testing.T, handler http.HandlerFunc, path string, input any, token string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(string(data)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Origin", "http://"+uiAddress)
	r.Header.Set("X-HubMaster", "admin")
	r.Header.Set("Cookie", "hm_session="+token)
	r.Host = uiAddress
	r.RemoteAddr = "127.0.0.1:50001"
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func TestPasswordResetAndAgentAudit(t *testing.T) {
	dir := t.TempDir()
	a, err := newAdmin(dir)
	if err != nil {
		t.Fatal(err)
	}
	req := map[string]string{"Password": "Z8!vQ2#mR7@k", "Key": a.state.Bootstrap}
	w := hit(t, a.dashboard, "/api/auth/setup", req, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var keys map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &keys); err != nil || !validHex(keys["recovery"], 24) {
		t.Fatal("missing recovery")
	}
	session := w.Result().Cookies()[0].Value
	w = hit(t, a.dashboard, "/api/auth/reset", map[string]string{"Password": "H3!rT8$vN9%j", "Key": keys["recovery"]}, "")
	if w.Code != 200 || !a.sessions[session].IsZero() {
		t.Fatal("password reset failed or session still active")
	}
	session = w.Result().Cookies()[0].Value
	var id string
	for key := range a.state.Hosts {
		id = key
	}
	dev := Device{ID: secret(16), Name: "USB test", Present: true, Controllable: true}
	e := event("file.renamed", `E:\new.txt`, `E:\old.txt`)
	hb := Heartbeat{Devices: []Device{dev}, Events: []Event{e}}
	for i := 0; i < 2; i++ {
		w = hit(t, a.agent, "/agent/"+id, hb, a.state.LocalToken)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if len(a.log.events) != 3 {
		t.Fatal("audit deduplication failed")
	}
	w = hit(t, a.dashboard, "/api/policy", map[string]string{"ID": id, "Device": dev.ID, "Action": "block"}, session)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = hit(t, a.agent, "/agent/"+id, hb, a.state.LocalToken)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "block") {
		t.Fatal("policy not delivered")
	}
	if _, err := newAdmin(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(a.log.path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "file.renamed", "file.modified", 1))
	if err := os.WriteFile(a.log.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAdmin(dir); err == nil {
		t.Fatal("altered log passed verification")
	}
}

func TestStrongPassword(t *testing.T) {
	for _, candidate := range []string{"123456", "Abc12!", "Pass1!", "aaaaaA", "A1!a", "Aa1!Aa", "Z8!vQ2", strings.Repeat("A", 129)} {
		if strongPassword(candidate) {
			t.Errorf("weak password accepted: %q", candidate)
		}
	}
	if !strongPassword("Z8!vQ2#mR7@k") {
		t.Fatal("valid password rejected")
	}
}

func TestStoragePolicyFollowsDeviceBetweenPorts(t *testing.T) {
	dir := t.TempDir()
	state, err := loadAgentState(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	id := secret(16)
	state.Policy.Devices = map[string]string{id: "block"}
	q := &offlineQueue{dir: dir}
	calls := map[string]bool{}
	control := func(instance string, block bool) error { calls[instance] = block; return nil }
	device := attachedDevice{Device: Device{ID: id, Kind: "storage", Controllable: true, Present: true}, Instance: "port-one"}
	state.reconcile([]attachedDevice{device}, q, filepath.Join(dir, "policy.json"), control)
	device.Instance = "port-two"
	state.reconcile([]attachedDevice{device}, q, filepath.Join(dir, "policy.json"), control)
	if !calls["port-one"] || !calls["port-two"] {
		t.Fatal("device was not blocked at both locations")
	}
	state.Policy.Devices[id] = "allow"
	state.reconcile([]attachedDevice{device}, q, filepath.Join(dir, "policy.json"), control)
	if calls["port-one"] || calls["port-two"] || len(state.Disabled) != 0 {
		t.Fatal("device nodes were not released")
	}
}

func TestAuditFiltersHostAndHidesRemovedAgent(t *testing.T) {
	dir := t.TempDir()
	a, err := newAdmin(dir)
	if err != nil {
		t.Fatal(err)
	}
	var localID string
	for id := range a.state.Hosts {
		localID = id
	}
	a.state.Hosts[localID].Name = "same"
	otherID := secret(16)
	a.state.Hosts[otherID] = &hostRecord{ClientHost: ClientHost{ID: otherID, Name: "same", Removed: true}}
	first := event("device.connected", "first", "")
	first.Host, first.HostID = "same", localID
	second := event("device.connected", "second", "")
	second.Host, second.HostID = "same", otherID
	legacy := event("device.connected", "legacy", "")
	legacy.Host = "same"
	if err := a.log.append([]Event{first, second, legacy}); err != nil {
		t.Fatal(err)
	}
	session := secret(32)
	a.sessions[session] = time.Now().Add(time.Hour)
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = uiAddress
		req.RemoteAddr = "127.0.0.1:50100"
		req.AddCookie(&http.Cookie{Name: "hm_session", Value: session})
		rec := httptest.NewRecorder()
		a.dashboard(rec, req)
		return rec
	}
	w := get("/api/audit?host=" + localID)
	var filtered struct{ Events []Event }
	if err := json.Unmarshal(w.Body.Bytes(), &filtered); err != nil || len(filtered.Events) != 1 || filtered.Events[0].Item != "first" {
		t.Fatalf("wrong host events: %s", w.Body.String())
	}
	w = get("/api/dashboard")
	var hosts []ClientHost
	if err := json.Unmarshal(w.Body.Bytes(), &hosts); err != nil || len(hosts) != 1 || hosts[0].ID != localID {
		t.Fatalf("removed host is visible: %s", w.Body.String())
	}
	w = get("/api/audit")
	if w.Code != 200 {
		t.Fatalf("global audit failed: %d", w.Code)
	}
}

func TestPairingOTPAndEnrollment(t *testing.T) {
	dir := t.TempDir()
	p := &pairing{path: filepath.Join(dir, "enrolled.json")}
	r := httptest.NewRequest("POST", "http://"+otpAddress+"/otp", nil)
	r.RemoteAddr = "127.0.0.1:50001"
	r.Header.Set("X-HubMaster", "agent")
	w := httptest.NewRecorder()
	p.local(w, r)
	if w.Code != 200 || !validOTP(p.otp) || time.Until(p.candidate.Expires) < 179*time.Second {
		t.Fatal("failed to issue six-digit OTP")
	}
	id := p.candidate.ID
	wrong := makeSPAKE("xxxxxx", id, false)
	w = hit(t, p.start, "/pair/start", pairStart{ID: id, Public: wrong.public}, "")
	var reply pairReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != 200 {
		t.Fatal("missing SPAKE reply")
	}
	_, _, proofB, err := wrong.derive(reply.Public, id)
	if err != nil || hmac.Equal(proofB, reply.Proof) {
		t.Fatal("incorrect code passed confirmation")
	}
	s := makeSPAKE(p.otp, id, false)
	w = hit(t, p.start, "/pair/start", pairStart{ID: id, Public: s.public}, "")
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != 200 {
		t.Fatal("missing SPAKE reply")
	}
	key, proof, expected, err := s.derive(reply.Public, id)
	if err != nil || !hmac.Equal(expected, reply.Proof) {
		t.Fatal("SPAKE confirmation failed")
	}
	enrolled := Enrollment{ID: secret(16), Token: secret(32), Pin: secret(32)}
	sealed, err := sealPair(key, id, enrolled)
	if err != nil {
		t.Fatal(err)
	}
	finish := pairFinish{Session: reply.Session, Proof: proof, Payload: sealed}
	w = hit(t, p.finish, "/pair/finish", finish, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result Enrollment
	if err := load(p.path, &result); err != nil || enrolled.Token != result.Token || result.Address != "127.0.0.1:"+tlsPort {
		t.Fatal("enrollment did not persist")
	}
	if w = hit(t, p.finish, "/pair/finish", finish, ""); w.Code != 403 {
		t.Fatal("replayed pairing accepted")
	}
}

func TestOfflineQueue(t *testing.T) {
	dir := t.TempDir()
	q := &offlineQueue{dir: dir}
	e := event("file.created", `E:\example.txt`, "")
	q.add(e)
	if _, _, err := q.next(); err != nil {
		t.Fatal(err)
	}
	restored := &offlineQueue{dir: dir}
	path, rows, err := restored.next()
	if err != nil || len(rows) != 1 || rows[0] != e || path == "" {
		t.Fatal("offline event was not restored", rows, err)
	}
}

func TestPinnedTransport(t *testing.T) {
	dir := t.TempDir()
	cert, err := serverCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	handshake := func(pin string) error {
		left, right := net.Pipe()
		defer left.Close()
		defer right.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		go func() {
			_ = tls.Server(left, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}).HandshakeContext(ctx)
		}()
		cfg := pinnedClient(pin).Transport.(*http.Transport).TLSClientConfig
		return tls.Client(right, cfg).HandshakeContext(ctx)
	}
	if err := handshake(fingerprint(cert.Certificate[0])); err != nil {
		t.Fatal(err)
	}
	if err := handshake(secret(32)); err == nil {
		t.Fatal("unexpected server certificate was accepted")
	}
}
