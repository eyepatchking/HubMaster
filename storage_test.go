package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQueueDrainsWhenAtCapacity(t *testing.T) {
	dir := t.TempDir()
	e := event("file.created", "saved", "")
	if err := save(filepath.Join(dir, "a.json"), []Event{e}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "z.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	q := &offlineQueue{dir: dir, pending: []Event{event("file.created", "pending", "")}}
	batch, rows, err := q.next()
	if err != nil || batch == "" || len(rows) != 1 || rows[0].ID != e.ID {
		t.Fatal("persisted batch must drain despite full queue", err)
	}
	if len(q.pending) != 1 {
		t.Fatal("pending event lost at quota")
	}
}

func TestQueueMemoryBoundAndGap(t *testing.T) {
	q := &offlineQueue{dir: filepath.Join(t.TempDir(), "missing")}
	for i := 0; i < 1005; i++ {
		q.add(event("test", "", ""))
	}
	if len(q.pending) != 1000 || q.dropped != 5 {
		t.Fatal("queue memory limit failed")
	}
	if err := os.Mkdir(q.dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := q.flush(); err != nil {
		t.Fatal(err)
	}
	if err := q.flush(); err != nil {
		t.Fatal(err)
	}
	if q.dropped != 0 {
		t.Fatal("loss count was not emitted after recovery")
	}
	entries, _ := os.ReadDir(q.dir)
	found := false
	for _, entry := range entries {
		var events []Event
		if err := load(filepath.Join(q.dir, entry.Name()), &events); err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Kind == "audit.gap" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("missing explicit loss report")
	}
}

func TestAuditMemoryBound(t *testing.T) {
	l := &ledger{}
	for i := 0; i < maxAuditEvents+5; i++ {
		l.remember(Event{Item: "record"})
	}
	if len(l.events) != maxAuditEvents {
		t.Fatal("audit memory window exceeds limit")
	}
}

func TestAuditRefusesOversizeAppend(t *testing.T) {
	dir := t.TempDir()
	l := &ledger{path: filepath.Join(dir, "audit.jsonl"), checkpoint: filepath.Join(dir, "head.json"), key: []byte("test"), seen: map[string]bool{}}
	f, err := os.Create(l.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAuditBytes); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := l.append([]Event{event("test", "", "")}); err == nil {
		t.Fatal("audit quota not enforced")
	}
	if l.head != "" || len(l.events) != 0 {
		t.Fatal("rejected append changed audit state")
	}
}
