package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

type offlineQueue struct {
	dir     string
	mu      sync.Mutex
	pending []Event
	dropped uint64
}

func (q *offlineQueue) add(e Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) >= 1000 {
		q.dropped++
		return
	}
	q.pending = append(q.pending, e)
	if len(q.pending) >= 100 {
		if err := q.flush(); err != nil {
			log.Print(err)
		}
	}
}

func (q *offlineQueue) flush() error {
	files, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	var total int64
	for _, file := range files {
		if file.IsDir() || !(strings.HasSuffix(file.Name(), ".json") || strings.Contains(file.Name(), ".corrupt-")) {
			continue
		}
		info, err := file.Info()
		if err != nil {
			return err
		}
		total += info.Size()
	}
	if q.dropped > 0 && len(q.pending) < 1000 {
		q.pending = append(q.pending, event("audit.gap", "offline queue", fmt.Sprintf("%d events lost while queue storage was unavailable", q.dropped)))
		q.dropped = 0
	}
	for len(q.pending) > 0 {
		path := filepath.Join(q.dir, time.Now().UTC().Format("20060102T150405.000000000")+"-"+secret(4)+".json")
		n := min(100, len(q.pending))
		raw, err := json.Marshal(q.pending[:n])
		if err != nil {
			return err
		}
		if total+int64(len(raw))+1 > 64<<20 {
			return errors.New("offline queue limit reached (64 MiB)")
		}
		if err := save(path, q.pending[:n]); err != nil {
			return err
		}
		total += int64(len(raw)) + 1
		q.pending = q.pending[n:]
	}
	return nil
}

func (q *offlineQueue) next() (string, []Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	flushErr := q.flush()
	files, err := os.ReadDir(q.dir)
	if err != nil {
		return "", nil, err
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		path := filepath.Join(q.dir, f.Name())
		var rows []Event
		err := load(path, &rows)
		if err == nil {
			if len(rows) == 0 || len(rows) > 100 {
				err = errors.New("invalid queue batch length")
			}
			for _, e := range rows {
				if !validHex(e.ID, 16) || e.Time.IsZero() || len(e.Kind) > 60 || len(e.Item) > 32768 || len(e.Detail) > 32768 {
					err = errors.New("invalid queue event")
					break
				}
			}
		}
		if err != nil {
			if renameErr := os.Rename(path, path+".corrupt-"+secret(4)); renameErr != nil {
				return "", nil, errors.Join(err, renameErr)
			}
			if len(q.pending) < 1000 {
				q.pending = append(q.pending, event("audit.gap", f.Name(), "Corrupt queue batch quarantined; original file retained"))
			}
			return "", nil, fmt.Errorf("corrupt queue batch quarantined: %s", f.Name())
		}
		return path, rows, nil
	}
	return "", nil, flushErr
}

type agentState struct {
	Policy     Policy
	Known      map[string]Device
	Disabled   map[string]string
	TrustedHID map[string]bool
	Errors     map[string]string
}

func loadAgentState(path string) (agentState, error) {
	s := agentState{Known: map[string]Device{}, Disabled: map[string]string{}, TrustedHID: map[string]bool{}, Errors: map[string]string{}}
	err := load(path, &s)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if s.Known == nil {
		s.Known = map[string]Device{}
	}
	if s.Disabled == nil {
		s.Disabled = map[string]string{}
	}
	if s.TrustedHID == nil {
		s.TrustedHID = map[string]bool{}
	}
	if s.Errors == nil {
		s.Errors = map[string]string{}
	}
	return s, err
}

func (s *agentState) reconcile(devices []attachedDevice, q *offlineQueue, path string, control func(string, bool) error) {
	active := map[string]bool{}
	for _, dev := range devices {
		active[dev.ID] = true
		if known, found := s.Known[dev.ID]; !found || !known.Present {
			q.add(event("device.connected", dev.Name, dev.Port))
			if dev.Risky && len(s.Known) > 0 && !s.TrustedHID[dev.ID] && s.Policy.Devices[dev.ID] != "allow" {
				q.add(event("device.hid_alert", dev.Name, dev.Hardware))
			}
		}
		_, disabled := s.Disabled[dev.Instance]
		dev.Controllable = dev.Controllable || disabled
		rule := s.Policy.Devices[dev.ID]
		block := rule == "block" || (rule != "allow" && s.Policy.ProtectHID && dev.Risky && !s.TrustedHID[dev.ID])
		if s.Policy.Remove {
			block = false
		}
		if block && dev.Controllable && !dev.Blocked && !disabled {
			// Record ownership before changing Windows so an interruption can
			// still be recovered. Never take ownership of an OS-disabled node.
			s.Disabled[dev.Instance] = dev.ID
			if err := save(path, s); err != nil {
				delete(s.Disabled, dev.Instance)
				q.add(event("device.error", dev.Name, err.Error()))
			} else {
				err := control(dev.Instance, true)
				if err == nil {
					dev.Blocked = true
					q.add(event("device.blocked", dev.Name, dev.Port))
					delete(s.Errors, dev.Instance)
				} else {
					delete(s.Disabled, dev.Instance)
					s.logError(q, dev.Instance, dev.Name, err)
				}
			}
		}
		if disabled && block && !dev.Blocked {
			if err := control(dev.Instance, true); err != nil {
				s.logError(q, dev.Instance, dev.Name, err)
			} else {
				dev.Blocked = true
			}
		}
		s.Known[dev.ID] = dev.Device
	}
	for id, dev := range s.Known {
		if !active[id] && dev.Present {
			dev.Present = false
			q.add(event("device.disconnected", dev.Name, dev.Port))
			s.Known[id] = dev
		}
	}
	for instance, id := range s.Disabled {
		dev := s.Known[id]
		rule := s.Policy.Devices[id]
		keep := rule == "block" || (rule != "allow" && s.Policy.ProtectHID && dev.Risky && !s.TrustedHID[id])
		if keep && !s.Policy.Remove {
			continue
		}
		if err := control(instance, false); err != nil {
			s.logError(q, instance, dev.Name, err)
			continue
		}
		delete(s.Disabled, instance)
		delete(s.Errors, instance)
		dev.Blocked = false
		s.Known[id] = dev
		q.add(event("device.allowed", dev.Name, dev.Port))
	}
	s.trimHistory()
}

func (s *agentState) logError(q *offlineQueue, instance, name string, err error) {
	if s.Errors[instance] != err.Error() {
		s.Errors[instance] = err.Error()
		q.add(event("device.error", name, err.Error()))
	}
}

type syncResult struct {
	policy Policy
	err    error
}

func runAgent(ctx context.Context, dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "removed.json")); err == nil {
		return removeAgentService()
	}
	settingsPath := filepath.Join(dir, "policy.json")
	state, err := loadAgentState(settingsPath)
	if err != nil {
		return err
	}
	enrolledPath := filepath.Join(dir, "enrolled.json")
	localPath := filepath.Join(dir, "local.json")
	var enrollment Enrollment
	findEnrollment := func() bool {
		for _, path := range []string{localPath, enrolledPath} {
			if load(path, &enrollment) == nil && validHex(enrollment.ID, 16) && validHex(enrollment.Token, 32) && validHex(enrollment.Pin, 32) && lanAddress(enrollment.Address) {
				return true
			}
		}
		return false
	}
	paired := findEnrollment()
	p := &pairing{path: enrolledPath, enrolled: paired}
	local, err := net.Listen("tcp4", otpAddress)
	if err != nil {
		return err
	}
	defer local.Close()
	ui := httpServer(http.HandlerFunc(p.local))
	defer ui.Close()
	if !paired {
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 47347})
		if err != nil {
			return err
		}
		defer udp.Close()
		go p.discover(udp)
		listener, err := net.Listen("tcp4", ":"+pairPort)
		if err != nil {
			return err
		}
		defer listener.Close()
		mux := http.NewServeMux()
		mux.HandleFunc("POST /pair/start", p.start)
		mux.HandleFunc("POST /pair/finish", p.finish)
		pairServer := httpServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !lanAddress(r.RemoteAddr) {
				reject(w, 403, "forbidden")
				return
			}
			mux.ServeHTTP(w, r)
		}))
		defer pairServer.Close()
		go pairServer.Serve(listener)
		// The service stops exposing pairing ports once enrollment is durable.
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					p.mu.Lock()
					complete := p.enrolled
					p.mu.Unlock()
					if complete {
						_ = udp.Close()
						_ = pairServer.Close()
						return
					}
				}
			}
		}()
	}
	q := &offlineQueue{dir: filepath.Join(dir, "queue")}
	if err := os.MkdirAll(q.dir, 0700); err != nil {
		return err
	}
	go ui.Serve(local)
	defer func() { q.mu.Lock(); defer q.mu.Unlock(); _ = q.flush() }()
	watchCtx, stopWatches := context.WithCancel(ctx)
	defer stopWatches()
	watches := volumeWatchers{active: map[string]volumeWatch{}}
	go auditProcesses(watchCtx, dir, q)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	results := make(chan syncResult, 1)
	var client *http.Client
	var prior []byte
	var nextSync time.Time
	var health string
	syncing := false
	for {
		if !paired && findEnrollment() {
			paired = true
			p.mu.Lock()
			p.enrolled = true
			p.mu.Unlock()
		}
		if paired && client == nil {
			client = pinnedClient(enrollment.Pin)
		}
		devices, ports, err := scanDevices(true)
		if err == nil {
			state.reconcile(devices, q, settingsPath, setDevice)
		} else {
			health = err.Error()
		}
		if err == nil && health != "" {
			health = ""
		}
		if state.Policy.Remove {
			stopWatches()
		} else {
			watches.update(watchCtx, q)
		}
		q.mu.Lock()
		if err := q.flush(); err != nil {
			health = err.Error()
		}
		q.mu.Unlock()
		raw, _ := json.Marshal(state)
		if string(raw) != string(prior) {
			if err := save(settingsPath, state); err == nil {
				prior = raw
			} else {
				health = err.Error()
			}
		}
		if client != nil && !syncing && !time.Now().Before(nextSync) {
			path, rows, err := q.next()
			if err != nil {
				health = err.Error()
			}
			if state.Policy.Remove && len(state.Disabled) == 0 && path == "" && err == nil {
				if err := finishRemoval(client, enrollment, dir); err == nil {
					return removeAgentService()
				} else {
					health = err.Error()
				}
			}
			known := state.inventory()
			nextSync = time.Now().Add(4 * time.Second)
			if len(rows) > 0 {
				nextSync = time.Now().Add(2 * time.Second)
			}
			syncing = true
			hb := Heartbeat{Devices: known, Ports: ports, Events: rows, Health: health}
			go func() {
				var result syncResult
				result.err = post(client, "https://"+enrollment.Address+"/agent/"+enrollment.ID, enrollment.Token, hb, &result.policy)
				if result.err == nil && path != "" {
					_ = os.Remove(path)
				}
				results <- result
			}()
		}
		select {
		case <-ctx.Done():
			return nil
		case result := <-results:
			syncing = false
			if result.err == nil {
				if result.policy.ProtectHID && !state.Policy.ProtectHID {
					clear(state.TrustedHID)
					for _, dev := range devices {
						if dev.Risky {
							state.TrustedHID[dev.ID] = true
						}
					}
				}
				state.Policy = result.policy
			} else {
				health = result.err.Error()
			}
		case <-tick.C:
		}
	}
}

func finishRemoval(client *http.Client, enrollment Enrollment, dir string) error {
	path := filepath.Join(dir, "removal-request.json")
	var e Event
	if err := load(path, &e); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		e = event("agent.removed", machineName(), "")
		if err := save(path, e); err != nil {
			return err
		}
	}
	var response Policy
	err := post(client, "https://"+enrollment.Address+"/agent/"+enrollment.ID, enrollment.Token, Heartbeat{Events: []Event{e}}, &response)
	if err != nil {
		return err
	}
	return save(filepath.Join(dir, "removed.json"), e)
}

func (s *agentState) inventory() []Device {
	known := make([]Device, 0, len(s.Known))
	for _, dev := range s.Known {
		known = append(known, dev)
	}
	slices.SortFunc(known, func(a, b Device) int {
		if a.Present != b.Present {
			if a.Present {
				return -1
			}
			return 1
		}
		if a.Blocked != b.Blocked {
			if a.Blocked {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name+a.ID, b.Name+b.ID)
	})
	if len(known) > 2048 {
		known = known[:2048]
	}
	return known
}

func (s *agentState) trimHistory() {
	if len(s.Known) <= 4096 {
		return
	}
	owned := map[string]bool{}
	for _, id := range s.Disabled {
		owned[id] = true
	}
	ids := make([]string, 0, len(s.Known))
	for id := range s.Known {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if len(s.Known) <= 4096 {
			return
		}
		dev := s.Known[id]
		if !dev.Present && !owned[id] && s.Policy.Devices[id] == "" {
			delete(s.Known, id)
		}
	}
}
