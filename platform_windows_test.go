package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUSBSerialIdentityAcrossPorts(t *testing.T) {
	root := pnpNode{instance: `USB\VID_1234&PID_5678\SERIAL-7`, capabilities: 0x10}
	disk := pnpNode{instance: `USBSTOR\DISK&VEN_TEST\LOCATION-ONE`, hardware: `USBSTOR\DISK&VEN_TEST`}
	first, _, _ := windowsDeviceIdentity(disk, root, "storage")
	disk.instance = `USBSTOR\DISK&VEN_TEST\LOCATION-TWO`
	second, _, _ := windowsDeviceIdentity(disk, root, "storage")
	if first != second {
		t.Fatal("serial-backed identity changed when the port changed")
	}
	root.instance = `USB\VID_1234&PID_5678\SERIAL-8`
	other, _, _ := windowsDeviceIdentity(disk, root, "storage")
	if first == other {
		t.Fatal("distinct serial numbers have the same identity")
	}
}

func TestPnPReadOnly(t *testing.T) {
	devices, ports, err := scanDevices(true)
	if err != nil {
		t.Skipf("PnP inventory unavailable to test user: %v", err)
	}
	t.Logf("Windows reported %d supported devices and %d connectors", len(devices), len(ports))
}

func TestFileAuditOnWindows(t *testing.T) {
	root := t.TempDir()
	q := &offlineQueue{dir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); watchVolume(ctx, root, q) }()
	original, newName := filepath.Join(root, "sample.txt"), filepath.Join(root, "renamed.txt")
	wanted := map[string]bool{"file.created": false, "file.renamed": false, "file.deleted": false}
	for i := 0; i < 12; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := os.WriteFile(original, []byte("audit test"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(original, newName); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(newName); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		q.mu.Lock()
		for _, e := range q.pending {
			if _, ok := wanted[e.Kind]; ok {
				wanted[e.Kind] = true
			}
		}
		q.mu.Unlock()
		if wanted["file.created"] && wanted["file.renamed"] && wanted["file.deleted"] {
			break
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("file watcher did not stop")
	}
	for kind, seen := range wanted {
		if !seen {
			t.Errorf("file watcher missed %s", kind)
		}
	}
}

func TestUpgradeBacksUpExistingBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Admin.exe")
	original := []byte("old binary")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	backedUp, err := backupInstalledBinary(path)
	if err != nil || !backedUp {
		t.Fatal(backedUp, err)
	}
	data, err := os.ReadFile(path + ".backup")
	if err != nil || string(data) != string(original) {
		t.Fatal("backup lost original", err)
	}
}
func TestUpgradeAcceptsMissingBinaryForRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Admin.exe")
	backedUp, err := backupInstalledBinary(path)
	if err != nil || backedUp {
		t.Fatal("missing binary must be repairable", backedUp, err)
	}
	if _, err := os.Stat(path + ".backup"); !os.IsNotExist(err) {
		t.Fatal("missing binary created a false backup")
	}
}
