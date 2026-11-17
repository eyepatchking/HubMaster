package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPasswordChangeRequiresSessionAndCurrentPassword(t *testing.T) {
	a, err := newAdmin(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldPassword := "Z8!vQ2#mR7@k"
	newPassword := "T5@mK9!vR2#x"
	w := hit(t, a.dashboard, "/api/auth/setup", map[string]string{"Password": oldPassword, "Key": a.state.Bootstrap}, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	oldSession := w.Result().Cookies()[0].Value
	var first map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &first)
	w = hit(t, a.dashboard, "/api/auth/change", map[string]string{"Password": newPassword, "CurrentPassword": oldPassword}, "")
	if w.Code != 401 {
		t.Fatal("unauthenticated change accepted")
	}
	w = hit(t, a.dashboard, "/api/auth/change", map[string]string{"Password": newPassword, "CurrentPassword": "wrong"}, oldSession)
	if w.Code != 401 {
		t.Fatal("wrong current password accepted")
	}
	a.nextAttempt = time.Time{}
	w = hit(t, a.dashboard, "/api/auth/change", map[string]string{"Password": newPassword, "CurrentPassword": oldPassword}, oldSession)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if !validHex(result["recovery"], 24) || result["recovery"] == first["recovery"] {
		t.Fatal("recovery key not rotated")
	}
	if _, ok := a.sessions[oldSession]; ok {
		t.Fatal("old session retained")
	}
	if equal(passHash(a.state.Salt, oldPassword), a.state.Password) || !equal(passHash(a.state.Salt, newPassword), a.state.Password) {
		t.Fatal("password change failed")
	}
	if equal(fingerprint([]byte(first["recovery"])), a.state.Recovery) {
		t.Fatal("old recovery retained")
	}
	for _, e := range a.log.events {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), newPassword) || strings.Contains(string(raw), result["recovery"]) {
			t.Fatal("credential leaked to audit")
		}
	}
	if _, err := newAdmin(a.dir); err != nil {
		t.Fatal(err)
	}
}

func TestLocalRecoveryPreservesEnrollmentAndAudit(t *testing.T) {
	a, err := newAdmin(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a.state.Password = "old hash"
	a.state.Recovery = "old key hash"
	a.sessions["old"] = time.Now().Add(time.Hour)
	beforeKey, beforeToken := a.state.AuditKey, a.state.LocalToken
	hosts := len(a.state.Hosts)
	if err := a.authorizeLocalRecovery(); err != nil {
		t.Fatal(err)
	}
	if a.state.Password != "" || a.state.Recovery != "" || !validHex(a.state.Bootstrap, 32) || len(a.sessions) != 0 {
		t.Fatal("recovery state invalid")
	}
	if a.state.AuditKey != beforeKey || a.state.LocalToken != beforeToken || len(a.state.Hosts) != hosts {
		t.Fatal("recovery destroyed enrollment")
	}
	if len(a.log.events) != 1 || a.log.events[0].Kind != "password.recovery_authorized" {
		t.Fatal("recovery not audited")
	}
	w := hit(t, a.dashboard, "/api/auth/setup", map[string]string{"Password": "T5@mK9!vR2#x", "Key": a.state.Bootstrap}, "")
	if w.Code != 200 {
		t.Fatal("recovery cannot create new password", w.Body.String())
	}
}

func TestAuditRotationMaintainsChainAndDetectsMissingArchive(t *testing.T) {
	a, err := newAdmin(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 140; i++ {
		if err := a.log.append([]Event{event("test", "record", strings.Repeat("x", 128<<10))}); err != nil {
			t.Fatal(err)
		}
	}
	archives, err := filepath.Glob(a.log.path + ".archive-*")
	if err != nil || len(archives) == 0 {
		t.Fatal("no archive created", err)
	}
	restored, err := newAdmin(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if restored.log.head != a.log.head || len(restored.log.events) != 140 {
		t.Fatal("rotation lost history")
	}
	if err := os.Remove(archives[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := newAdmin(a.dir); err == nil {
		t.Fatal("missing archive passed verification")
	}
}

func TestCorruptQueueDoesNotBlockHealthyBatches(t *testing.T) {
	dir := t.TempDir()
	q := &offlineQueue{dir: dir}
	e := event("test", "healthy", "")
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := save(filepath.Join(dir, "b.json"), []Event{e}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.next(); err == nil {
		t.Fatal("corruption not reported")
	}
	found := false
	for i := 0; i < 3; i++ {
		p, rows, err := q.next()
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.ID == e.ID {
				found = true
			}
		}
		if p != "" {
			_ = os.Remove(p)
		}
	}
	if !found {
		t.Fatal("healthy batch stranded")
	}
	quarantined, _ := filepath.Glob(filepath.Join(dir, "*.corrupt-*"))
	if len(quarantined) != 1 {
		t.Fatal("original corrupt file not retained")
	}
}

func TestLinuxAuditParser(t *testing.T) {
	raw := `type=SYSCALL msg=audit(1700000000.123:42): pid=33 exe="/usr/bin/cp" key="hubmaster_v2"
type=CWD msg=audit(1700000000.123:42): cwd="/media/USB"
type=PATH msg=audit(1700000000.123:42): item=0 name="file name.txt" nametype=CREATE
type=PATH msg=audit(1700000000.123:42): item=1 name="/etc/private" nametype=NORMAL
`
	rows, err := parseLinuxAudit(raw, map[string]string{"/media/USB": "disk"})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if rows[0].Item != "/media/USB/file name.txt" || !strings.Contains(rows[0].Detail, "/usr/bin/cp") {
		t.Fatal(rows)
	}
	again, _ := parseLinuxAudit(raw, map[string]string{"/media/USB": "disk"})
	if again[0].ID != rows[0].ID {
		t.Fatal("retry IDs unstable")
	}
	if linuxAuditString("2f746d702f78") != "/tmp/x" {
		t.Fatal("hex path not decoded")
	}
}

func TestHeartbeatInventoryStaysWithinProtocolLimit(t *testing.T) {
	s := agentState{Known: map[string]Device{}}
	for i := 0; i < 2100; i++ {
		id := secret(16)
		s.Known[id] = Device{ID: id, Name: "old"}
	}
	s.Known["present"] = Device{ID: "present", Name: "current", Present: true}
	rows := s.inventory()
	if len(rows) != 2048 || rows[0].ID != "present" {
		t.Fatal("present device lost or protocol limit exceeded")
	}
}

func TestAuditRecoversUncommittedPartialTail(t *testing.T) {
	a, err := newAdmin(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.log.append([]Event{event("test", "committed", "")}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(a.log.path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("{incomplete")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := newAdmin(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.log.events) != 2 || restored.log.events[1].Kind != "audit.gap" {
		t.Fatal("partial tail recovery not reported")
	}
	partial, _ := filepath.Glob(a.log.path + ".partial-*")
	if len(partial) != 1 {
		t.Fatal("original fragment lost")
	}
	if _, err := newAdmin(a.dir); err != nil {
		t.Fatal("repaired chain invalid", err)
	}
}
