package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func systemCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", name), args...)
}

func monitoredVolumes() map[string]string {
	result := map[string]string{}
	drives, err := windows.GetLogicalDrives()
	if err != nil {
		return result
	}
	systemDisk, systemKnown := diskNumber(`\\.\` + os.Getenv("SystemDrive"))
	for drive := uint32(0); drive < 26; drive++ {
		if drives&(1<<drive) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+drive)
		typeID := windows.GetDriveType(windows.StringToUTF16Ptr(root))
		if typeID != windows.DRIVE_REMOVABLE && typeID != windows.DRIVE_FIXED && typeID != windows.DRIVE_CDROM {
			continue
		}
		h, err := openDevice(`\\.\`+root[:2], 0)
		if err != nil {
			continue
		}
		num, numKnown := handleDiskNumber(h)
		var query [12]byte
		var desc [1024]byte
		n, err := ioctl(h, 0x002d1400, query[:], desc[:]) // IOCTL_STORAGE_QUERY_PROPERTY
		windows.CloseHandle(h)
		bus := binary.LittleEndian.Uint32(desc[28:])
		external := err == nil && n >= 32 && (bus == 7 || bus == 12 || bus == 13) // USB, SD, MMC
		if typeID != windows.DRIVE_REMOVABLE && typeID != windows.DRIVE_CDROM && !external {
			continue
		}
		if typeID == windows.DRIVE_FIXED && (!numKnown || !systemKnown || num == systemDisk) {
			continue
		}
		var volume [512]uint16
		if err := windows.GetVolumeNameForVolumeMountPoint(windows.StringToUTF16Ptr(root), &volume[0], uint32(len(volume))); err == nil {
			result[root] = windows.UTF16ToString(volume[:])
		} else {
			result[root] = root
		}
	}
	return result
}

type volumeWatch struct {
	id   string
	stop context.CancelFunc
	dead *atomic.Bool
}

type volumeWatchers struct{ active map[string]volumeWatch }

func (v *volumeWatchers) update(ctx context.Context, q *offlineQueue) {
	roots := monitoredVolumes()
	for root, w := range v.active {
		if roots[root] != w.id || w.dead.Load() {
			w.stop()
			delete(v.active, root)
		}
	}
	for root, id := range roots {
		if _, ok := v.active[root]; ok {
			continue
		}
		watchCtx, cancel := context.WithCancel(ctx)
		dead := new(atomic.Bool)
		v.active[root] = volumeWatch{id: id, stop: cancel, dead: dead}
		go func() {
			defer dead.Store(true)
			watchVolume(watchCtx, root, q)
		}()
	}
}

func watchVolume(ctx context.Context, root string, q *offlineQueue) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(root), windows.FILE_LIST_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	signal, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return
	}
	defer windows.CloseHandle(signal)
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return
	}
	defer windows.CloseHandle(stop)
	done := make(chan struct{})
	exit := make(chan struct{})
	go func() {
		defer close(exit)
		select {
		case <-ctx.Done():
			_ = windows.SetEvent(stop)
		case <-done:
		}
	}()
	defer func() { close(done); <-exit }()
	buffer := make([]byte, 64*1024)
	var rename string
	for {
		_ = windows.ResetEvent(signal)
		overlap := windows.Overlapped{HEvent: signal}
		err := windows.ReadDirectoryChanges(h, &buffer[0], uint32(len(buffer)), true, windows.FILE_NOTIFY_CHANGE_FILE_NAME|windows.FILE_NOTIFY_CHANGE_DIR_NAME|windows.FILE_NOTIFY_CHANGE_SIZE|windows.FILE_NOTIFY_CHANGE_LAST_WRITE, nil, &overlap, 0)
		if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
			if errors.Is(err, windows.ERROR_NOTIFY_ENUM_DIR) {
				q.add(event("audit.gap", root, err.Error()))
			}
			return
		}
		which, err := windows.WaitForMultipleObjects([]windows.Handle{stop, signal}, false, windows.INFINITE)
		var n uint32
		if err != nil || which == windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(h, &overlap)
			_ = windows.GetOverlappedResult(h, &overlap, &n, true)
			return
		}
		err = windows.GetOverlappedResult(h, &overlap, &n, false)
		if err != nil || n == 0 || int(n) > len(buffer) {
			if n == 0 && err == nil || errors.Is(err, windows.ERROR_NOTIFY_ENUM_DIR) {
				q.add(event("audit.gap", root, "ReadDirectoryChangesW overflow"))
				continue
			}
			return
		}
		rename = parseChanges(buffer[:n], root, rename, q)
	}
}

func parseChanges(data []byte, root, rename string, q *offlineQueue) string {
	for len(data) >= 12 {
		next := int(binary.LittleEndian.Uint32(data))
		action := binary.LittleEndian.Uint32(data[4:])
		size := int(binary.LittleEndian.Uint32(data[8:]))
		if size > len(data)-12 || size%2 != 0 {
			break
		}
		chars := make([]uint16, size/2)
		for i := range chars {
			chars[i] = binary.LittleEndian.Uint16(data[12+2*i:])
		}
		path := filepath.Join(root, string(utf16.Decode(chars)))
		if rename != "" && action != windows.FILE_ACTION_RENAMED_NEW_NAME {
			q.add(event("file.rename_from", rename, ""))
			rename = ""
		}
		switch action {
		case windows.FILE_ACTION_ADDED:
			q.add(event("file.created", path, ""))
		case windows.FILE_ACTION_REMOVED:
			q.add(event("file.deleted", path, ""))
		case windows.FILE_ACTION_MODIFIED:
			q.add(event("file.modified", path, ""))
		case windows.FILE_ACTION_RENAMED_OLD_NAME:
			rename = path
		case windows.FILE_ACTION_RENAMED_NEW_NAME:
			q.add(event("file.renamed", path, rename))
			rename = ""
		}
		if next < 12 || next >= len(data) {
			break
		}
		data = data[next:]
	}
	return rename
}

type windowsEvents struct {
	Events []struct {
		System struct {
			Record  uint64 `xml:"EventRecordID"`
			Code    int    `xml:"EventID"`
			Created struct {
				Time string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
		} `xml:"System"`
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"EventData>Data"`
	} `xml:"Event"`
}

func eventQuery(ctx context.Context, args ...string) (windowsEvents, error) {
	cmd := systemCommand(ctx, "wevtutil.exe", append([]string{"qe", "Security", "/f:xml", "/e:Events", "/uni:true"}, args...)...)
	raw, err := cmd.Output()
	if err != nil {
		return windowsEvents{}, err
	}
	if bytes.HasPrefix(raw, []byte{0xff, 0xfe}) || (len(raw) > 3 && raw[0] == '<' && raw[1] == 0) {
		raw = bytes.TrimPrefix(raw, []byte{0xff, 0xfe})
		chars := make([]uint16, len(raw)/2)
		for i := range chars {
			chars[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		raw = []byte(string(utf16.Decode(chars)))
	}
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}))
	if bytes.HasPrefix(raw, []byte("<?xml")) {
		if end := bytes.Index(raw, []byte("?>")); end >= 0 {
			raw = raw[end+2:]
		}
	}
	var rows windowsEvents
	if len(raw) > 0 {
		err = xml.Unmarshal(raw, &rows)
	}
	return rows, err
}

func volumePrefixes() map[string]string {
	prefixes := map[string]string{}
	for root := range monitoredVolumes() {
		prefixes[strings.ToUpper(root)] = root
		var dst [4096]uint16
		if _, err := windows.QueryDosDevice(windows.StringToUTF16Ptr(root[:2]), &dst[0], uint32(len(dst))); err == nil {
			prefixes[strings.ToUpper(windows.UTF16ToString(dst[:]))+`\`] = root
		}
	}
	return prefixes
}

func auditProcesses(ctx context.Context, dir string, q *offlineQueue) {
	path := filepath.Join(dir, "security-bookmark.json")
	var cursor uint64
	if err := load(path, &cursor); err != nil {
		probe, cancel := context.WithTimeout(ctx, 8*time.Second)
		rows, err := eventQuery(probe, "/rd:true", "/c:1")
		cancel()
		if err != nil {
			q.add(event("audit.error", "Security", err.Error()))
			return
		}
		if len(rows.Events) > 0 {
			cursor = rows.Events[0].System.Record
		}
	}
	tick := time.NewTicker(4 * time.Second)
	defer tick.Stop()
	var lastError string
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		check, cancel := context.WithTimeout(ctx, 8*time.Second)
		query := fmt.Sprintf("/q:*[System[(EventID=4663 or EventID=1102) and EventRecordID>%d]]", cursor)
		rows, err := eventQuery(check, query, "/rd:false", "/c:300")
		cancel()
		if err != nil {
			if err.Error() != lastError {
				q.add(event("audit.error", "Security", err.Error()))
				lastError = err.Error()
			}
			continue
		}
		lastError = ""
		if len(rows.Events) == 0 {
			// EventRecordID restarts after Security is cleared. Probe outside
			// the bookmark filter so the old cursor cannot hide the reset.
			probe, stop := context.WithTimeout(ctx, 8*time.Second)
			latest, probeErr := eventQuery(probe, "/rd:true", "/c:1")
			stop()
			if probeErr == nil && len(latest.Events) > 0 && latest.Events[0].System.Record < cursor {
				cursor = 0
				q.add(event("audit.gap", "Security", "Security record sequence reset; resuming from available records"))
			}
			continue
		}
		prefixes := volumePrefixes()
		for _, row := range rows.Events {
			cursor = row.System.Record
			if row.System.Code == 1102 {
				q.add(event("audit.gap", "Security", "Windows event log cleared"))
				continue
			}
			values := map[string]string{}
			for _, field := range row.Data {
				values[field.Name] = field.Value
			}
			mask, err := strconv.ParseUint(values["AccessMask"], 0, 32)
			if err != nil || mask&0x10116 == 0 {
				continue
			}
			object := values["ObjectName"]
			for prefix, root := range prefixes {
				if strings.HasPrefix(strings.ToUpper(object), prefix) {
					e := event("file.process", root+object[len(prefix):], values["ProcessName"]+" · "+values["AccessMask"])
					if when, err := time.Parse(time.RFC3339Nano, row.System.Created.Time); err == nil {
						e.Time = when
					}
					e.ID = fingerprint([]byte(fmt.Sprintf("%d/%s", cursor, row.System.Created.Time)))[:32]
					q.add(e)
					break
				}
			}
		}
		q.mu.Lock()
		if q.flush() == nil {
			_ = save(path, cursor)
		}
		q.mu.Unlock()
	}
}
