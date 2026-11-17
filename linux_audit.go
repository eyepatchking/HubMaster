package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var auditFields = regexp.MustCompile("([a-zA-Z_]+)=([\"](?:[^\"]*)[\"]|[^ ]+)")
var auditIdentity = regexp.MustCompile(`msg=audit\((\d+)\.(\d+):(\d+)\)`)

func linuxAuditString(value string) string {
	if strings.HasPrefix(value, "\"") {
		v, err := strconv.Unquote(value)
		if err == nil {
			return v
		}
		return ""
	}
	if b, err := hex.DecodeString(value); err == nil {
		return string(b)
	}
	return ""
}

func parseLinuxAudit(raw string, roots map[string]string) ([]Event, error) {
	type record struct {
		exe, cwd, pid string
		names         []string
		when          time.Time
	}
	records := map[string]*record{}
	order := []string{}
	scan := bufio.NewScanner(strings.NewReader(raw))
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		line := scan.Text()
		id := auditIdentity.FindStringSubmatch(line)
		if id == nil {
			continue
		}
		identity := id[1] + "." + id[2] + ":" + id[3]
		r := records[identity]
		if r == nil {
			r = &record{}
			records[identity] = r
			order = append(order, identity)
			seconds, _ := strconv.ParseInt(id[1], 10, 64)
			fraction := id[2] + strings.Repeat("0", 9)
			nanos, _ := strconv.ParseInt(fraction[:9], 10, 64)
			r.when = time.Unix(seconds, nanos).UTC()
		}
		fields := map[string]string{}
		for _, m := range auditFields.FindAllStringSubmatch(line, -1) {
			fields[m[1]] = m[2]
		}
		switch fields["type"] {
		case "SYSCALL":
			r.exe = linuxAuditString(fields["exe"])
			r.pid = fields["pid"]
		case "CWD":
			r.cwd = linuxAuditString(fields["cwd"])
		case "PATH":
			if fields["nametype"] != "PARENT" {
				if name := linuxAuditString(fields["name"]); name != "" {
					r.names = append(r.names, name)
				}
			}
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	var events []Event
	for _, id := range order {
		r := records[id]
		if r.exe == "" {
			continue
		}
		seen := map[string]bool{}
		for _, name := range r.names {
			if !path.IsAbs(name) {
				if !path.IsAbs(r.cwd) {
					continue
				}
				name = path.Join(r.cwd, name)
			}
			name = path.Clean(name)
			if seen[name] {
				continue
			}
			seen[name] = true
			for root := range roots {
				if name == root || strings.HasPrefix(name, strings.TrimSuffix(root, "/")+"/") {
					e := event("file.process", name, r.exe+" · PID "+r.pid)
					e.Time = r.when
					e.ID = fingerprint([]byte("linux-audit/" + id + "/" + name))[:32]
					events = append(events, e)
					break
				}
			}
		}
	}
	if len(order) > 0 && len(events) == 0 && len(roots) > 0 { /* Events outside current mounts are deliberately excluded. */
	}
	if len(raw) > 8<<20 {
		return nil, errors.New("audit query too large")
	}
	return events, nil
}
