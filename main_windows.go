package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var role = "Admin"
var user32 = windows.NewLazySystemDLL("user32.dll")

type serviceHandler struct {
	runner func(context.Context, string) error
	dir    string
}

func (s serviceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, state chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	state <- svc.Status{State: svc.StartPending}
	f, err := os.OpenFile(filepath.Join(s.dir, "service.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err == nil {
		defer f.Close()
		log.SetOutput(f)
	}
	go func() { done <- s.runner(ctx, s.dir) }()
	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	state <- status
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Print(err)
				return true, 1
			}
			return false, 0
		case command := <-req:
			switch command.Cmd {
			case svc.Interrogate:
				state <- status
			case svc.Stop, svc.Shutdown:
				state <- svc.Status{State: svc.StopPending, WaitHint: 8000}
				cancel()
				select {
				case <-done:
				case <-time.After(7 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func main() {
	args := os.Args[1:]
	arg := ""
	if len(args) > 0 {
		arg = args[0]
	}
	if strings.HasPrefix(role, "Setup-") {
		if err := setup(strings.TrimPrefix(role, "Setup-")); err != nil {
			message("HubMaster Setup", err.Error(), 0x10)
		}
		return
	}
	switch arg {
	case "--service":
		name, runner := adminService, runAdmin
		if role == "Agent" {
			name, runner = agentService, runAgent
		}
		if err := validateSecureDir(dataPath(role)); err != nil {
			log.Fatal(err)
		}
		if err := svc.Run(name, serviceHandler{runner: runner, dir: dataPath(role)}); err != nil {
			log.Fatal(err)
		}
	case "--recover":
		if role != "Admin" {
			return
		}
		if err := recoverAdmin(); err != nil {
			message("HubMaster Recovery", err.Error(), 0x10)
		}
	case "--uninstall":
		if err := uninstall(role); err != nil {
			message("HubMaster", err.Error(), 0x30)
		}
	default:
		if role == "Agent" {
			showOTP()
		} else {
			openAdmin()
		}
	}
}

func message(title, body string, style uintptr) int {
	r, _, _ := user32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(body))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(title))), style)
	return int(r)
}

func showOTP() {
	client := safeClient(&http.Transport{})
	req, _ := http.NewRequest("POST", "http://"+otpAddress+"/otp", nil)
	req.Header.Set("X-HubMaster", "agent")
	var res *http.Response
	for i := 0; i < 10; i++ {
		var err error
		res, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if res == nil {
		message("HubMaster Agent", "Agent xizmati ishga tushmagan. / Служба агента не запущена. / Agent service is unavailable.", 0x30)
		return
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case 409:
		message("HubMaster Agent", "Agent ulangan. / Агент подключён. / Agent is paired.", 0x40)
	case 429:
		message("HubMaster Agent", "Kod muddati tugashini kuting. / Дождитесь истечения кода. / Wait for the code to expire.", 0x30)
	case 200:
		var data struct {
			OTP     string
			Expires time.Time
		}
		if json.NewDecoder(io.LimitReader(res.Body, 1024)).Decode(&data) != nil || !validOTP(data.OTP) {
			return
		}
		title := "HubMaster Agent"
		body := fmt.Sprintf("OTP    %s\n\nAmal qiladi / Действует до / Valid until   %s\n\nHubMaster Admin → Scan", data.OTP, data.Expires.Local().Format("15:04:05"))
		ms := time.Until(data.Expires).Milliseconds()
		proc := user32.NewProc("MessageBoxTimeoutW")
		if ms > 0 && proc.Find() == nil {
			proc.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(body))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(title))), 0x40, 0, uintptr(ms))
		} else if ms > 0 {
			message(title, body, 0x40)
		}
	default:
		message("HubMaster Agent", "Agent xatosi. / Ошибка агента. / Agent error.", 0x30)
	}
}

func openAdmin() {
	client := safeClient(&http.Transport{})
	address := "http://" + uiAddress
	var status struct{ Setup bool }
	available := false
	for i := 0; i < 16; i++ {
		res, err := client.Get(address + "/api/status")
		if err == nil {
			available = res.StatusCode == 200 && json.NewDecoder(io.LimitReader(res.Body, 1024)).Decode(&status) == nil
			res.Body.Close()
			if available {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !available {
		message("HubMaster Admin", "Admin xizmati ishga tushmagan. / Служба не запущена. / Admin service is unavailable.", 0x30)
		return
	}
	if status.Setup {
		if !windows.GetCurrentProcessToken().IsElevated() {
			path, _ := os.Executable()
			_ = launch(path, "", "runas")
			return
		}
		var s adminState
		if err := load(filepath.Join(dataPath("Admin"), "state.json"), &s); err != nil {
			message("HubMaster Admin", err.Error(), 0x10)
			return
		}
		address += "/#setup=" + s.Bootstrap
	}
	for _, root := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles")} {
		path := filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe")
		if _, err := os.Stat(path); err == nil {
			if err := exec.Command(path, "--app="+address).Start(); err == nil {
				return
			}
		}
	}
	if err := launch(address, "", "open"); err != nil {
		message("HubMaster Admin", err.Error(), 0x10)
	}
}

func launch(path, args, verb string) error {
	return windows.ShellExecute(0, windows.StringToUTF16Ptr(verb), windows.StringToUTF16Ptr(path), windows.StringToUTF16Ptr(args), nil, 1)
}

func waitForComponent(name string) error {
	address, path := otpAddress, "/health"
	if name == "Admin" {
		address, path = uiAddress, "/api/status"
	}
	client := safeClient(&http.Transport{})
	client.Timeout = time.Second
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		res, err := client.Get("http://" + address + path)
		if err == nil {
			var status struct{ Version string }
			ready := res.StatusCode == 200 && json.NewDecoder(io.LimitReader(res.Body, 1024)).Decode(&status) == nil && status.Version == productVersion
			res.Body.Close()
			if ready {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("HubMaster %s did not start. See %s", name, filepath.Join(dataPath(name), "service.log"))
}

func removeAgentService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(agentService)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Delete()
}

func recoverAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		return launch(self, "--recover", "runas")
	}
	if message("HubMaster Recovery", "Parol va recovery kalitini bekor qilib, yangi parol yaratish? Qurilma qoidalari va audit saqlanadi.\nСбросить пароль и ключ? Правила и аудит сохранятся.\nReset password and recovery key? Device policies and audit will be preserved.", 0x31) != 1 {
		return nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(adminService)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	if err := waitStopped(s); err != nil {
		return err
	}
	restarted := false
	defer func() {
		if !restarted {
			_ = s.Start()
		}
	}()
	if err := validateSecureDir(dataPath("Admin")); err != nil {
		return err
	}
	a, err := newAdmin(dataPath("Admin"))
	if err != nil {
		return err
	}
	if err := a.authorizeLocalRecovery(); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}
	restarted = true
	if err := waitForComponent("Admin"); err != nil {
		return err
	}
	openAdmin()
	return nil
}
