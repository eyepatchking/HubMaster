package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const productVersion = "2.3.0"
const sysUSB = "/sys/bus/usb/devices"

func replaceFile(from, to string) error { return os.Rename(from, to) }

func enableBroadcast(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1) })
	if err != nil {
		return err
	}
	return optionErr
}

func readValue(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func rootDevice() string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 5 && fields[4] == "/" {
			path, err := filepath.EvalSymlinks(filepath.Join("/sys/dev/block", fields[2]))
			if err != nil || strings.Contains(path, "/virtual/") {
				return ""
			}
			return path
		}
	}
	return ""
}

func scanDevices(includePorts bool) ([]attachedDevice, []Port, error) {
	entries, err := os.ReadDir(sysUSB)
	if err != nil {
		return nil, nil, err
	}
	root := rootDevice()
	devices := []attachedDevice{}
	ports := []Port{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.Contains(name, ":") {
			continue
		}
		path := filepath.Join(sysUSB, name)
		class := strings.ToLower(readValue(filepath.Join(path, "bInterfaceClass")))
		kind := ""
		switch class {
		case "08":
			kind = "storage"
		case "03":
			kind = "hid"
			switch readValue(filepath.Join(path, "bInterfaceProtocol")) {
			case "01":
				kind = "keyboard"
			case "02":
				kind = "mouse"
			}
		case "07":
			kind = "printer"
		default:
			continue
		}
		usbName := strings.SplitN(name, ":", 2)[0]
		parent := filepath.Join(sysUSB, usbName)
		if strings.ToLower(readValue(filepath.Join(parent, "bDeviceClass"))) == "e0" {
			continue
		}
		if strings.Contains(strings.ToLower(readValue(filepath.Join(parent, "product"))), "bluetooth") {
			continue
		}
		vendor, product := readValue(filepath.Join(parent, "idVendor")), readValue(filepath.Join(parent, "idProduct"))
		if vendor == "" || product == "" {
			continue
		}
		serial := readValue(filepath.Join(parent, "serial"))
		instance := name
		identity := strings.Join([]string{vendor, product, serial, kind, readValue(filepath.Join(path, "bInterfaceNumber"))}, "|")
		if serial == "" {
			identity += "|" + usbName
		}
		label := strings.TrimSpace(readValue(filepath.Join(parent, "manufacturer")) + " " + readValue(filepath.Join(parent, "product")))
		if label == "" {
			label = "USB " + vendor + ":" + product
		}
		actual, _ := filepath.EvalSymlinks(parent)
		controllable := actual != "" && (kind != "storage" || root != "" && root != actual && !strings.HasPrefix(root, actual+string(os.PathSeparator)))
		blocked := readValue(filepath.Join(path, "authorized")) == "0"
		hardware := "VID_" + strings.ToUpper(vendor) + " PID_" + strings.ToUpper(product)
		port := "USB port " + usbName
		id := fingerprint([]byte(identity))[:32]
		devices = append(devices, attachedDevice{Device: Device{ID: id, Name: label, Kind: kind, Port: port, Serial: serial, Hardware: hardware, Identity: map[bool]string{true: "serial", false: "instance"}[serial != ""], Blocked: blocked, Present: true, Controllable: controllable, Risky: kind == "keyboard" || kind == "mouse" || kind == "hid"}, Instance: instance})
		if includePorts {
			ports = append(ports, Port{ID: fingerprint([]byte(usbName))[:16], Name: port, Kind: "usb", Connected: true})
		}
	}
	if includePorts {
		ports = append(ports, linuxConnectorPorts()...)
	}
	extra, extraPorts := linuxBlockInventory(root)
	devices = append(devices, extra...)
	if includePorts {
		ports = append(ports, extraPorts...)
	}
	slices.SortFunc(devices, func(a, b attachedDevice) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(ports, func(a, b Port) int { return strings.Compare(a.ID, b.ID) })
	unique := ports[:0]
	for _, p := range ports {
		if len(unique) == 0 || unique[len(unique)-1].ID != p.ID {
			unique = append(unique, p)
		}
	}
	return devices, unique, nil
}

func setDevice(instance string, block bool) error {
	if strings.HasPrefix(instance, "block|") {
		return setLinuxBlockDevice(instance, block)
	}
	if instance == "" || filepath.Base(instance) != instance || !strings.Contains(instance, ":") {
		return errors.New("invalid USB interface")
	}
	path := filepath.Join(sysUSB, instance, "authorized")
	value := "1"
	if block {
		value = "0"
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		if !block && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !block {
		if _, err := os.Stat(filepath.Join(sysUSB, instance, "driver")); err == nil {
			return nil
		}
		return os.WriteFile("/sys/bus/usb/drivers_probe", []byte(instance), 0600)
	}
	return nil
}

func removeAgentService() error {
	cmd := exec.Command("systemctl", "disable", "hubmaster-agent.service")
	return cmd.Run()
}

type volumeWatch struct {
	cancel context.CancelFunc
	id     string
	dead   *atomic.Bool
}
type volumeWatchers struct{ active map[string]volumeWatch }

func linuxVolumes() map[string]string {
	result := map[string]string{}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return result
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	root := rootDevice()
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 6 || fields[4] == "/" {
			continue
		}
		path, err := filepath.EvalSymlinks(filepath.Join("/sys/dev/block", fields[2]))
		if err != nil || sameLinuxDisk(path, root) || !(strings.Contains(path, "/usb") || strings.Contains(path, "/mmc_host/") || strings.HasPrefix(filepath.Base(path), "sr")) {
			continue
		}
		mount := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(fields[4])
		result[mount] = path
	}
	return result
}

func (v *volumeWatchers) update(ctx context.Context, q *offlineQueue) {
	mounts := linuxVolumes()
	for root, watch := range v.active {
		if id, ok := mounts[root]; !ok || id != watch.id || watch.dead.Load() {
			watch.cancel()
			delete(v.active, root)
		}
	}
	for root, id := range mounts {
		if _, ok := v.active[root]; ok {
			continue
		}
		child, cancel := context.WithCancel(ctx)
		dead := new(atomic.Bool)
		v.active[root] = volumeWatch{cancel: cancel, id: id, dead: dead}
		go func() { defer dead.Store(true); watchLinux(child, root, q) }()
	}
}

type linuxChange struct {
	wd           int32
	mask, cookie uint32
	name         string
}

func decodeLinuxChanges(data []byte) ([]linuxChange, error) {
	var result []linuxChange
	for len(data) > 0 {
		if len(data) < 16 {
			return nil, errors.New("truncated inotify header")
		}
		size := int(binary.LittleEndian.Uint32(data[12:16]))
		if size > len(data)-16 {
			return nil, errors.New("truncated inotify name")
		}
		name := strings.TrimRight(string(data[16:16+size]), "\x00")
		if strings.Contains(name, "/") || name == "." || name == ".." {
			return nil, errors.New("invalid inotify name")
		}
		result = append(result, linuxChange{wd: int32(binary.LittleEndian.Uint32(data[:4])), mask: binary.LittleEndian.Uint32(data[4:8]), cookie: binary.LittleEndian.Uint32(data[8:12]), name: name})
		data = data[16+size:]
	}
	return result, nil
}

func watchLinux(ctx context.Context, root string, q *offlineQueue) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		q.add(event("audit.error", root, err.Error()))
		return
	}
	defer unix.Close(fd)
	paths := map[int32]string{}
	addTree := func(path string) {
		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				q.add(event("audit.error", p, err.Error()))
				return nil
			}
			if d.IsDir() {
				wd, err := unix.InotifyAddWatch(fd, p, unix.IN_CREATE|unix.IN_MODIFY|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_ONLYDIR|unix.IN_DONT_FOLLOW)
				if err != nil {
					q.add(event("audit.error", p, err.Error()))
				} else {
					paths[int32(wd)] = p
				}
			}
			return nil
		})
	}
	type move struct {
		path      string
		at        time.Time
		directory bool
	}
	moves := map[uint32]move{}
	removeTree := func(root string) {
		for wd, p := range paths {
			if p == root || strings.HasPrefix(p, root+"/") {
				_, _ = unix.InotifyRmWatch(fd, uint32(wd))
				delete(paths, wd)
			}
		}
	}
	flushMoves := func(force bool) {
		for cookie, m := range moves {
			if force || time.Since(m.at) > time.Second {
				q.add(event("file.rename_from", m.path, "Destination outside watched tree or missing"))
				if m.directory {
					removeTree(m.path)
				}
				delete(moves, cookie)
			}
		}
	}
	addTree(root)
	buffer := make([]byte, 64<<10)
	for ctx.Err() == nil {
		flushMoves(false)
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, 250)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			q.add(event("audit.error", root, err.Error()))
			return
		}
		n, err := unix.Read(fd, buffer)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			q.add(event("audit.error", root, err.Error()))
			return
		}
		changes, err := decodeLinuxChanges(buffer[:n])
		if err != nil {
			q.add(event("audit.gap", root, err.Error()))
			continue
		}
		for _, e := range changes {
			if e.mask&unix.IN_Q_OVERFLOW != 0 {
				flushMoves(true)
				q.add(event("audit.gap", root, "inotify overflow"))
				addTree(root)
				continue
			}
			parent, ok := paths[e.wd]
			if !ok {
				continue
			}
			name := filepath.Join(parent, e.name)
			if e.mask&unix.IN_IGNORED != 0 {
				delete(paths, e.wd)
				continue
			}
			if e.mask&unix.IN_MOVED_FROM != 0 {
				moves[e.cookie] = move{path: name, at: time.Now(), directory: e.mask&unix.IN_ISDIR != 0}
				continue
			}
			if e.mask&unix.IN_MOVED_TO != 0 {
				if old, ok := moves[e.cookie]; ok {
					q.add(event("file.renamed", name, old.path))
					delete(moves, e.cookie)
					if old.directory {
						for wd, p := range paths {
							if p == old.path || strings.HasPrefix(p, old.path+"/") {
								paths[wd] = name + strings.TrimPrefix(p, old.path)
							}
						}
					}
				} else {
					q.add(event("file.created", name, "Moved into watched volume"))
				}
				if e.mask&unix.IN_ISDIR != 0 {
					addTree(name)
				}
				continue
			}
			if e.mask&unix.IN_CREATE != 0 {
				q.add(event("file.created", name, ""))
				if e.mask&unix.IN_ISDIR != 0 {
					addTree(name)
				}
			}
			if e.mask&unix.IN_MODIFY != 0 {
				q.add(event("file.modified", name, ""))
			}
			if e.mask&unix.IN_DELETE != 0 {
				q.add(event("file.deleted", name, ""))
			}
			if e.mask&unix.IN_DELETE_SELF != 0 && parent == root {
				q.add(event("audit.gap", root, "Watched mount removed"))
				return
			}
		}
	}
	flushMoves(true)
}

type auditOutput struct {
	data  []byte
	limit int
}

func (o *auditOutput) Write(p []byte) (int, error) {
	if len(o.data)+len(p) > o.limit {
		return 0, errors.New("audit command output exceeded limit")
	}
	o.data = append(o.data, p...)
	return len(p), nil
}

func auditTool(name string) string {
	for _, dir := range []string{"/usr/sbin", "/sbin"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func auditCommand(ctx context.Context, tool string, args ...string) ([]byte, error) {
	child, stop := context.WithTimeout(ctx, 8*time.Second)
	defer stop()
	cmd := exec.CommandContext(child, tool, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out := &auditOutput{limit: 8 << 20}
	stderr := &auditOutput{limit: 16 << 10}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		return out.data, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(stderr.data)))
	}
	return out.data, nil
}

func auditProcesses(ctx context.Context, dir string, q *offlineQueue) {
	ctl, search := auditTool("auditctl"), auditTool("ausearch")
	if ctl == "" || search == "" {
		q.add(event("audit.error", "Linux", "Install auditd for process attribution"))
		<-ctx.Done()
		return
	}
	const key = "hubmaster_v2"
	// This reserved key is owned by HubMaster; never remove unrelated rules.
	if _, err := auditCommand(ctx, ctl, "-D", "-k", key); err != nil {
		q.add(event("audit.error", "Linux", err.Error()))
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, _ = auditCommand(cleanup, ctl, "-D", "-k", key)
	}()
	watched := map[string]string{}
	checkpoint := filepath.Join(dir, "linux-audit.checkpoint")
	staged := filepath.Join(dir, "linux-audit.pending")
	tick := time.NewTicker(4 * time.Second)
	defer tick.Stop()
	lastError := ""
	for ctx.Err() == nil {
		mounts := linuxVolumes()
		for mount, id := range watched {
			if mounts[mount] != id {
				for _, arch := range []string{"b64", "b32"} {
					_, _ = auditCommand(ctx, ctl, "-d", "always,exit", "-F", "arch="+arch, "-F", "dir="+mount, "-F", "perm=wa", "-F", "key="+key)
				}
				delete(watched, mount)
			}
		}
		for mount, id := range mounts {
			if watched[mount] == id {
				continue
			}
			ok := true
			for _, arch := range []string{"b64", "b32"} {
				if _, err := auditCommand(ctx, ctl, "-a", "always,exit", "-F", "arch="+arch, "-F", "dir="+mount, "-F", "perm=wa", "-F", "key="+key); err != nil {
					ok = false
					if err.Error() != lastError {
						q.add(event("audit.error", mount, err.Error()))
						lastError = err.Error()
					}
				}
			}
			if ok {
				watched[mount] = id
			} else {
				for _, arch := range []string{"b64", "b32"} {
					_, _ = auditCommand(ctx, ctl, "-d", "always,exit", "-F", "arch="+arch, "-F", "dir="+mount, "-F", "perm=wa", "-F", "key="+key)
				}
			}
		}
		if len(watched) > 0 {
			_ = os.Remove(staged)
			args := []string{"-k", key, "--raw", "--checkpoint", staged}
			if data, err := os.ReadFile(checkpoint); err == nil {
				if err := os.WriteFile(staged, data, 0600); err != nil {
					q.add(event("audit.error", "Linux", err.Error()))
					return
				}
			} else {
				args = append(args, "--start", "recent")
			}
			raw, err := auditCommand(ctx, search, args...)
			if err != nil {
				var exit *exec.ExitError
				if errors.As(err, &exit) && (exit.ExitCode() == 10 || exit.ExitCode() == 11 || exit.ExitCode() == 12) {
					q.add(event("audit.gap", "Linux", "Audit checkpoint unavailable; recovering by timestamp"))
					raw, err = auditCommand(ctx, search, append(args, "--start", "checkpoint")...)
				}
			}
			if err != nil && !strings.Contains(strings.ToLower(err.Error()), "no matches") {
				if err.Error() != lastError {
					q.add(event("audit.error", "Linux", err.Error()))
					lastError = err.Error()
				}
			} else {
				events, parseErr := parseLinuxAudit(string(raw), mounts)
				if parseErr != nil {
					q.add(event("audit.gap", "Linux", parseErr.Error()))
				} else {
					for _, e := range events {
						q.add(e)
					}
					q.mu.Lock()
					flushErr := q.flush()
					q.mu.Unlock()
					if flushErr == nil {
						if _, err := os.Stat(staged); err == nil {
							_ = os.Rename(staged, checkpoint)
						}
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func linuxMain() {
	if len(os.Args) > 1 && os.Args[1] == "--remove-local" {
		if err := linuxLocalRemoval(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Agent blocks released. Run: sudo apt purge hubmaster-agent")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--otp" {
		client := safeClient(&http.Transport{})
		req, _ := http.NewRequest("POST", "http://"+otpAddress+"/otp", nil)
		req.Header.Set("X-HubMaster", "agent")
		res, err := client.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer res.Body.Close()
		var result struct {
			OTP     string
			Expires time.Time
			Error   string
		}
		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if res.StatusCode != 200 {
			fmt.Println(result.Error)
			return
		}
		fmt.Printf("HubMaster OTP: %s\nValid until: %s\n", result.OTP, result.Expires.Local().Format("15:04:05"))
		fmt.Println("Press Enter to close.")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := os.MkdirAll("/var/lib/hubmaster-agent", 0700); err != nil {
		log.Fatal(err)
	}
	if err := validateLinuxDataDir("/var/lib/hubmaster-agent"); err != nil {
		log.Fatal(err)
	}
	if err := runAgent(ctx, "/var/lib/hubmaster-agent"); err != nil {
		log.Fatal(err)
	}
}

func main() { linuxMain() }

func linuxConnectorPorts() []Port {
	var ports []Port
	entries, _ := os.ReadDir(sysUSB)
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ":") {
			continue
		}
		count, _ := strconv.Atoi(readValue(filepath.Join(sysUSB, name, "maxchild")))
		if count < 1 || count > 127 {
			continue
		}
		prefix := name + "."
		if strings.HasPrefix(name, "usb") {
			prefix = strings.TrimPrefix(name, "usb") + "-"
		}
		for i := 1; i <= count; i++ {
			child := prefix + strconv.Itoa(i)
			_, err := os.Stat(filepath.Join(sysUSB, child))
			ports = append(ports, Port{ID: fingerprint([]byte(child))[:16], Name: "USB port " + child, Kind: "usb", Connected: err == nil})
		}
	}
	connectors, _ := filepath.Glob("/sys/class/typec/port*")
	for _, p := range connectors {
		name := filepath.Base(p)
		if strings.Contains(name, "-") {
			continue
		}
		_, err := os.Stat(p + "-partner")
		ports = append(ports, Port{ID: fingerprint([]byte("typec/" + name))[:16], Name: "USB-C connector " + name, Kind: "usb_c", Connected: err == nil})
	}
	return ports
}

func linuxBlockInventory(root string) ([]attachedDevice, []Port) {
	var devices []attachedDevice
	var ports []Port
	entries, _ := os.ReadDir("/sys/class/block")
	for _, entry := range entries {
		name := entry.Name()
		kind := ""
		if strings.HasPrefix(name, "mmcblk") && !strings.Contains(name, "p") && !strings.Contains(name, "boot") && !strings.Contains(name, "rpmb") {
			kind = "sd"
		}
		if strings.HasPrefix(name, "sr") {
			kind = "optical"
		}
		if kind == "" {
			continue
		}
		base := filepath.Join("/sys/class/block", name)
		actual, _ := filepath.EvalSymlinks(base)
		if sameLinuxDisk(actual, root) {
			continue
		}
		serial := readValue(filepath.Join(base, "device", "cid"))
		if serial == "" {
			serial = readValue(filepath.Join(base, "device", "serial"))
		}
		id := fingerprint([]byte(kind + "/" + actual + "/" + serial))[:32]
		label := strings.TrimSpace(readValue(filepath.Join(base, "device", "name")) + " " + readValue(filepath.Join(base, "device", "model")))
		if label == "" {
			label = kind + " " + name
		}
		port := Port{ID: id, Name: label, Kind: kind, Connected: readValue(filepath.Join(base, "size")) != "0"}
		ports = append(ports, port)
		if !port.Connected {
			continue
		}
		driverPath, _ := filepath.EvalSymlinks(filepath.Join(base, "device", "driver"))
		nodePath, _ := filepath.EvalSymlinks(filepath.Join(base, "device"))
		bus, driver := "mmc", "mmcblk"
		if kind == "optical" {
			bus, driver = "scsi", "sr"
		}
		instance := "block|" + bus + "|" + driver + "|" + filepath.Base(nodePath)
		_, unbindErr := os.Stat(filepath.Join(driverPath, "unbind"))
		controllable := root != "" && !sameLinuxDisk(actual, root) && driverPath == filepath.Join("/sys/bus", bus, "drivers", driver) && unbindErr == nil
		if serial != "" {
			id = fingerprint([]byte(kind + "/" + serial))[:32]
			ports[len(ports)-1].ID = id
		}
		devices = append(devices, attachedDevice{Device: Device{ID: id, Name: label, Kind: kind, Port: label, Serial: serial, Identity: "instance", Present: true, Controllable: controllable}, Instance: instance})
	}
	return devices, ports
}

func validateLinuxDataDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe HubMaster data directory: root ownership and mode 0700 required")
	}
	return nil
}

func linuxLocalRemoval() error {
	if os.Geteuid() != 0 {
		return errors.New("run with sudo: hubmaster-agent --remove-local")
	}
	dir := "/var/lib/hubmaster-agent"
	if err := validateLinuxDataDir(dir); err != nil {
		return err
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	if err := exec.CommandContext(ctx, "systemctl", "stop", "hubmaster-agent.service").Run(); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = exec.Command("systemctl", "start", "hubmaster-agent.service").Run()
		}
	}()
	path := filepath.Join(dir, "policy.json")
	state, err := loadAgentState(path)
	if err != nil {
		return err
	}
	for instance := range state.Disabled {
		if err := setDevice(instance, false); err != nil {
			return err
		}
		delete(state.Disabled, instance)
		if err := save(path, state); err != nil {
			return err
		}
	}
	state.Policy = Policy{}
	if err := save(path, state); err != nil {
		return err
	}
	if err := save(filepath.Join(dir, "removed.json"), event("agent.removed", machineName(), "Authorized by local root administrator")); err != nil {
		return err
	}
	if err := exec.CommandContext(ctx, "systemctl", "disable", "hubmaster-agent.service").Run(); err != nil {
		return err
	}
	complete = true
	return nil
}

func sameLinuxDisk(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	disk := func(p string) string {
		if i := strings.Index(p, "/block/"); i >= 0 {
			tail := p[i+7:]
			name := strings.SplitN(tail, "/", 2)[0]
			return p[:i+7] + name
		}
		return p
	}
	return disk(a) == disk(b)
}

func setLinuxBlockDevice(instance string, block bool) error {
	parts := strings.Split(instance, "|")
	if len(parts) != 4 {
		return errors.New("invalid block device descriptor")
	}
	bus, driver, node := parts[1], parts[2], parts[3]
	if !(bus == "mmc" && driver == "mmcblk" || bus == "scsi" && driver == "sr") || node == "" || node == "." || node == ".." {
		return errors.New("unsupported block driver")
	}
	for _, c := range node {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ':' || c == '.' || c == '_' || c == '-') {
			return errors.New("invalid block device node")
		}
	}
	if _, err := os.Stat(filepath.Join("/sys/bus", bus, "devices", node)); err != nil {
		if !block && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	action := "bind"
	if block {
		action = "unbind"
	} else {
		bound, _ := filepath.EvalSymlinks(filepath.Join("/sys/bus", bus, "devices", node, "driver"))
		if bound == filepath.Join("/sys/bus", bus, "drivers", driver) {
			return nil
		}
	}
	return os.WriteFile(filepath.Join("/sys/bus", bus, "drivers", driver, action), []byte(node), 0600)
}
