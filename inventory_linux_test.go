package main

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxChangeDecoder(t *testing.T) {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 7)
	binary.LittleEndian.PutUint32(b[4:], unix.IN_MOVED_FROM)
	binary.LittleEndian.PutUint32(b[8:], 99)
	binary.LittleEndian.PutUint32(b[12:], 8)
	copy(b[16:], "old.txt")
	rows, err := decodeLinuxChanges(b)
	if err != nil || len(rows) != 1 || rows[0].cookie != 99 || rows[0].name != "old.txt" {
		t.Fatal(rows, err)
	}
	if _, err := decodeLinuxChanges(b[:17]); err == nil {
		t.Fatal("truncated record accepted")
	}
}
func TestLinuxSystemDiskPartitions(t *testing.T) {
	if !sameLinuxDisk("/sys/devices/usb1/block/sda/sda1", "/sys/devices/usb1/block/sda/sda2") {
		t.Fatal("system disk sibling partition not protected")
	}
	if sameLinuxDisk("/sys/devices/usb1/block/sda/sda1", "/sys/devices/usb2/block/sdb/sdb1") {
		t.Fatal("different disks merged")
	}
}
func TestLinuxWatcherRenameAndCancellation(t *testing.T) {
	dir := t.TempDir()
	q := &offlineQueue{dir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); watchLinux(ctx, dir, q) }()
	found := false
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		a, b := filepath.Join(dir, "before.txt"), filepath.Join(dir, "after.txt")
		if err := os.WriteFile(a, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(a, b); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		q.mu.Lock()
		for _, e := range q.pending {
			if e.Kind == "file.renamed" && e.Item == b && e.Detail == a {
				found = true
			}
		}
		q.mu.Unlock()
		_ = os.Remove(b)
		if found {
			break
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop")
	}
	if !found {
		t.Fatal("rename pair not observed")
	}
}

func TestLinuxBlockDescriptorRejectsTraversal(t *testing.T) {
	for _, value := range []string{"block|mmc|mmcblk|../../etc", "block|pci|xhci|node", "block|scsi|sr|..", "block|mmc|mmcblk|"} {
		if err := setLinuxBlockDevice(value, true); err == nil {
			t.Fatal("unsafe block descriptor accepted", value)
		}
	}
}
