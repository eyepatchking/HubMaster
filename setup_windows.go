package main

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const productVersion = "2.3.2"
const setupMagic = "HUBMZIP2"

func installPath() string { return filepath.Join(os.Getenv("ProgramFiles"), "HubMaster V2") }

func exePath(component string) string { return filepath.Join(installPath(), component+".exe") }

func createSecureDir(path string) error {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(windows.StringToUTF16Ptr(path), &sa)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return validateSecureDir(path)
}

func validateSecureDir(path string) error {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("Unsafe HubMaster data directory: %s", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("Missing directory access restrictions: %s", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("Unsupported directory access entry: %s", path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid != "S-1-5-18" && sid != "S-1-5-32-544" {
			return fmt.Errorf("Directory access is too broad: %s", path)
		}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	ownerID := owner.String()
	if ownerID != "S-1-5-18" && ownerID != "S-1-5-32-544" {
		return fmt.Errorf("Unexpected directory owner: %s", path)
	}
	return nil
}

func packageFiles(path string) (*os.File, *zip.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*os.File, *zip.Reader, error) { f.Close(); return nil, nil, err }
	stat, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	var header [16]byte
	if _, err = f.ReadAt(header[:], stat.Size()-16); err != nil {
		return fail(err)
	}
	length := int64(binary.LittleEndian.Uint64(header[8:]))
	if string(header[:8]) != setupMagic || length <= 0 || length > stat.Size()-16 {
		return fail(errors.New("Installer payload is invalid"))
	}
	z, err := zip.NewReader(io.NewSectionReader(f, stat.Size()-16-length, length), length)
	if err != nil {
		return fail(err)
	}
	return f, z, nil
}

func extractBinary(z *zip.Reader, component string) error {
	src, err := z.Open(component + ".exe")
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.CreateTemp(installPath(), ".install-*.exe")
	if err != nil {
		return err
	}
	defer os.Remove(dst.Name())
	_, err = io.Copy(dst, src)
	err = errors.Join(err, dst.Close())
	if err != nil {
		return err
	}
	return replaceFile(dst.Name(), exePath(component))
}

func setup(component string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return launch(self, "", "runas")
	}
	f, payload, err := packageFiles(self)
	if err != nil {
		return err
	}
	defer f.Close()
	title := "HubMaster " + component + " Setup"
	if message(title, "HubMaster "+component+" "+productVersion+"\n\nO‘rnatishni boshlash / Начать установку / Start setup", 0x41) != 1 {
		return nil
	}
	if message(title, "Windows fon xizmati / Служба Windows / Windows background service\n\n"+installPath()+"\n\nO‘rnatish / Установить / Install", 0x41) != 1 {
		return nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	target := agentService
	if component == "Admin" {
		target = adminService
	}
	if existing, err := m.OpenService(target); err == nil {
		existing.Close()
		if err := upgrade(m, payload, component); err != nil {
			return err
		}
		return launch(exePath(component), "", "open")
	}
	if err := createSecureDir(filepath.Dir(dataPath("Agent"))); err != nil {
		return err
	}
	if err := os.MkdirAll(installPath(), 0755); err != nil {
		return err
	}
	components := []string{"Agent"}
	if component == "Admin" {
		components = append(components, "Admin")
		if existing, err := m.OpenService(agentService); err == nil {
			existing.Close()
			return errors.New("This PC already has the standalone HubMaster Agent. Remove it from its HubMaster Admin before installing Admin on this PC.")
		}
	}
	if _, err := os.Stat(filepath.Join(dataPath("Agent"), "removed.json")); err == nil {
		if err := os.Rename(dataPath("Agent"), dataPath("Agent")+".archive-"+secret(5)); err != nil {
			return err
		}
	}
	created := []*mgr.Service{}
	success := false
	defer func() {
		for i := len(created) - 1; i >= 0; i-- {
			s := created[i]
			if !success {
				_, _ = s.Control(svc.Stop)
				_ = s.Delete()
			}
			s.Close()
		}
	}()
	for _, part := range components {
		dir := dataPath(part)
		if err := createSecureDir(dir); err != nil {
			return err
		}
		if err := extractBinary(payload, part); err != nil {
			return err
		}
		name, description := agentService, "HubMaster removable device monitoring and policy"
		if part == "Admin" {
			name, description = adminService, "HubMaster local console and LAN coordination"
		}
		s, err := m.CreateService(name, exePath(part), mgr.Config{StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, DisplayName: "HubMaster " + part, Description: description}, "--service")
		if err != nil {
			return err
		}
		created = append(created, s)
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 15 * time.Second}}, 86400); err != nil {
			return err
		}
		if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	rules := []firewallRule{{"HubMaster V2 discovery", "UDP", scanPort, "Agent"}, {"HubMaster V2 pairing", "TCP", pairPort, "Agent"}}
	if component == "Admin" {
		rules = []firewallRule{{"HubMaster V2 transport", "TCP", tlsPort, "Admin"}}
	}
	for _, rule := range rules {
		if err := rule.install(ctx); err != nil {
			return err
		}
	}
	auditErr := systemCommand(ctx, "auditpol.exe", "/set", "/subcategory:{0CCE9245-69AE-11D9-BED3-505054503030}", "/success:enable").Run()
	for i := len(created) - 1; i >= 0; i-- {
		if err := created[i].Start(); err != nil {
			return err
		}
		if err := waitForComponent(components[i]); err != nil {
			return err
		}
	}
	success = true
	for _, part := range components {
		if part == "Agent" && component == "Admin" {
			continue
		}
		_ = registerApplication(part)
		_ = createShortcut(part)
		if part == "Admin" {
			_ = createRecoveryShortcut()
		}
	}
	if auditErr != nil {
		message(title, "Windows Security audit policy could not be enabled. File change notifications are available. Process names require the Removable Storage audit policy.", 0x30)
	}
	message(title, "O‘rnatildi / Установлено / Installed\n\nHubMaster "+component, 0x40)
	return launch(exePath(component), "", "open")
}

func upgrade(m *mgr.Mgr, payload *zip.Reader, component string) error {
	if err := validateSecureDir(filepath.Dir(dataPath("Agent"))); err != nil {
		return err
	}
	if err := validateSecureDir(dataPath("Agent")); err != nil {
		return err
	}
	if component == "Admin" {
		if err := validateSecureDir(dataPath("Admin")); err != nil {
			return err
		}
	}
	parts := []string{"Agent"}
	if component == "Admin" {
		parts = append(parts, "Admin")
	}
	services := make([]*mgr.Service, 0, len(parts))
	stopped := false
	success := false
	backedUp := map[string]bool{}
	defer func() {
		if stopped && !success {
			for _, s := range services {
				_, _ = s.Control(svc.Stop)
				_ = waitStopped(s)
			}
			for _, part := range parts {
				if backup := exePath(part) + ".backup"; backedUp[part] {
					_ = replaceFile(backup, exePath(part))
				}
			}
			for i := len(services) - 1; i >= 0; i-- {
				_ = services[i].Start()
			}
		}
		for _, s := range services {
			s.Close()
		}
	}()
	for _, part := range parts {
		name := agentService
		if part == "Admin" {
			name = adminService
		}
		s, err := m.OpenService(name)
		if err != nil {
			return err
		}
		services = append(services, s)
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
		stopped = true
		if err := waitStopped(s); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(installPath(), 0755); err != nil {
		return err
	}
	for _, part := range parts {
		saved, err := backupInstalledBinary(exePath(part))
		backedUp[part] = saved

		if err != nil {
			return err
		}
	}
	for _, part := range parts {
		if err := extractBinary(payload, part); err != nil {
			return err
		}
	}
	for i := len(services) - 1; i >= 0; i-- {
		if err := services[i].Start(); err != nil {
			return err
		}
		if err := waitForComponent(parts[i]); err != nil {
			for _, s := range services {
				_, _ = s.Control(svc.Stop)
				_ = waitStopped(s)
			}
			return err
		}
	}
	success = true
	for _, part := range parts {
		_ = os.Remove(exePath(part) + ".backup")
	}
	_ = registerApplication(component)
	_ = createShortcut(component)
	if component == "Admin" {
		_ = createRecoveryShortcut()
	}
	return nil
}

type firewallRule struct{ name, protocol, port, part string }

func (r firewallRule) install(ctx context.Context) error {
	_ = systemCommand(ctx, "netsh.exe", "advfirewall", "firewall", "delete", "rule", "name="+r.name).Run()
	out, err := systemCommand(ctx, "netsh.exe", "advfirewall", "firewall", "add", "rule", "name="+r.name, "dir=in", "action=allow", "protocol="+r.protocol, "localport="+r.port, "remoteip=LocalSubnet", "program="+exePath(r.part), "profile=any").CombinedOutput()
	if err != nil {
		return fmt.Errorf("Windows Firewall: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallKey(part string) string {
	return `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HubMasterV2` + part
}

func registerApplication(part string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey(part), registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return errors.Join(
		key.SetStringValue("DisplayName", "HubMaster "+part),
		key.SetStringValue("DisplayVersion", productVersion),
		key.SetStringValue("Publisher", "HubMaster"),
		key.SetStringValue("DisplayIcon", exePath(part)),
		key.SetStringValue("InstallLocation", installPath()),
		key.SetStringValue("UninstallString", `"`+exePath(part)+`" --uninstall`),
		key.SetDWordValue("NoModify", 1),
		key.SetDWordValue("NoRepair", 1),
	)
}

func shortcutPath(part string) (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "HubMaster "+part+".lnk"), nil
}

type comObject struct{ table *[24]uintptr }

func (o *comObject) call(index int, args ...uintptr) uintptr {
	res, _, _ := syscall.SyscallN(o.table[index], append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...)
	return res
}

func createShortcut(part string) error { return createShortcutFor(part, false) }

func createRecoveryShortcut() error { return createShortcutFor("Admin", true) }

func createShortcutFor(part string, recovery bool) error {
	path, err := shortcutPath(part)
	if recovery {
		path = strings.TrimSuffix(path, ".lnk") + " Recovery.lnk"
	}
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ole := windows.NewLazySystemDLL("ole32.dll")
	ret, _, _ := ole.NewProc("CoInitializeEx").Call(0, 2)
	if int32(ret) < 0 {
		return fmt.Errorf("COM 0x%x", ret)
	}
	defer ole.NewProc("CoUninitialize").Call()
	class := guid("{00021401-0000-0000-c000-000000000046}")
	linkIID := guid("{000214f9-0000-0000-c000-000000000046}")
	fileIID := guid("{0000010b-0000-0000-c000-000000000046}")
	var link *comObject
	ret, _, _ = ole.NewProc("CoCreateInstance").Call(uintptr(unsafe.Pointer(&class)), 0, 1, uintptr(unsafe.Pointer(&linkIID)), uintptr(unsafe.Pointer(&link)))
	if int32(ret) < 0 {
		return fmt.Errorf("ShellLink 0x%x", ret)
	}
	defer link.call(2)
	target := windows.StringToUTF16Ptr(exePath(part))
	if ret := link.call(20, uintptr(unsafe.Pointer(target))); int32(ret) < 0 {
		return fmt.Errorf("SetPath 0x%x", ret)
	}
	runtime.KeepAlive(target)
	if recovery {
		arg := windows.StringToUTF16Ptr("--recover")
		if ret := link.call(11, uintptr(unsafe.Pointer(arg))); int32(ret) < 0 {
			return fmt.Errorf("SetArguments 0x%x", ret)
		}
		runtime.KeepAlive(arg)
	}
	var persist *comObject
	if ret := link.call(0, uintptr(unsafe.Pointer(&fileIID)), uintptr(unsafe.Pointer(&persist))); int32(ret) < 0 {
		return fmt.Errorf("IPersistFile 0x%x", ret)
	}
	defer persist.call(2)
	p := windows.StringToUTF16Ptr(path)
	ret = persist.call(6, uintptr(unsafe.Pointer(p)), 1)
	runtime.KeepAlive(p)
	if int32(ret) < 0 {
		return fmt.Errorf("Save shortcut 0x%x", ret)
	}
	return nil
}

func uninstall(part string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return launch(exePath(part), "--uninstall", "runas")
	}
	if part == "Admin" {
		return uninstallAdmin()
	}
	if _, err := os.Stat(filepath.Join(dataPath("Agent"), "removed.json")); err != nil {
		if message("HubMaster Agent", "Admin paneli mavjud bo‘lmasa, Windows administratori sifatida agentni olib tashlaysizmi? HubMaster bloklari yechiladi.\nRemove this agent using Windows administrator authority? HubMaster device blocks will be released. The remote console may show this PC as offline.", 0x31) != 1 {
			return nil
		}
		if err := removeLocalAgent(); err != nil {
			return err
		}
	}
	if message("HubMaster", "Agent fayllarini olib tashlash / Удалить файлы агента / Remove Agent application files", 0x31) != 1 {
		return nil
	}
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey(part))
	if path, err := shortcutPath(part); err == nil {
		_ = os.Remove(path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, name := range []string{"HubMaster V2 discovery", "HubMaster V2 pairing"} {
		_ = systemCommand(ctx, "netsh.exe", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	}
	return scheduleExecutableRemoval(exePath(part))
}

func uninstallAdmin() error {
	var existing adminState
	if load(filepath.Join(dataPath("Admin"), "state.json"), &existing) == nil {
		remote := 0
		for _, h := range existing.Hosts {
			if !h.Local && !h.Removed {
				remote++
			}
		}
		if remote > 0 && message("HubMaster Admin", fmt.Sprintf("%d ta masofaviy agent ulangan. Adminni o‘chirishdan oldin ularni paneldan olib tashlash tavsiya etiladi. Davom etilsinmi?\n%d remote agents remain paired. Their policies stay active if this Admin is removed. Continue?", remote, remote), 0x31) != 1 {
			return nil
		}
	}
	if message("HubMaster", "HubMaster Admin’ni olib tashlash. Audit arxivi saqlanadi.\nУдалить HubMaster Admin. Архив аудита сохранится.\nRemove HubMaster Admin. The audit archive is retained.", 0x31) != 1 {
		return nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	var services []*mgr.Service
	finished := false
	defer func() {
		for i := len(services) - 1; i >= 0; i-- {
			if !finished {
				_ = services[i].Start()
			}
			services[i].Close()
		}
	}()
	for _, name := range []string{agentService, adminService} {
		s, err := m.OpenService(name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		if err != nil {
			return err
		}
		services = append(services, s)
		if _, err = s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
		if err := waitStopped(s); err != nil {
			return err
		}
	}
	path := filepath.Join(dataPath("Agent"), "policy.json")
	state, err := loadAgentState(path)
	if err != nil {
		return err
	}
	for instance := range state.Disabled {
		if err := setDevice(instance, false); err != nil {
			return err
		}
		delete(state.Disabled, instance)
	}
	state.Policy = Policy{}
	if err := save(path, state); err != nil {
		return err
	}
	for _, s := range services {
		if err := s.Delete(); err != nil {
			return err
		}
	}
	finished = true
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey("Admin"))
	if path, err := shortcutPath("Admin"); err == nil {
		_ = os.Remove(path)
		_ = os.Remove(strings.TrimSuffix(path, ".lnk") + " Recovery.lnk")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	_ = systemCommand(ctx, "netsh.exe", "advfirewall", "firewall", "delete", "rule", "name=HubMaster V2 transport").Run()
	if err := os.Remove(exePath("Agent")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return scheduleExecutableRemoval(exePath("Admin"))
}

func waitStopped(s *mgr.Service) error {
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s did not stop", s.Name)
}

func removeLocalAgent() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(agentService)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	restart := false
	if s != nil {
		defer s.Close()
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
		if err := waitStopped(s); err != nil {
			return err
		}
		restart = true
		defer func() {
			if restart {
				_ = s.Start()
			}
		}()
	}
	statePath := filepath.Join(dataPath("Agent"), "policy.json")
	state, err := loadAgentState(statePath)
	if err != nil {
		return err
	}
	for instance := range state.Disabled {
		if err := setDevice(instance, false); err != nil {
			return err
		}
		delete(state.Disabled, instance)
		if err := save(statePath, state); err != nil {
			return err
		}
	}
	state.Policy = Policy{}
	if err := save(statePath, state); err != nil {
		return err
	}
	if err := save(filepath.Join(dataPath("Agent"), "removed.json"), event("agent.removed", machineName(), "Authorized by local Windows administrator")); err != nil {
		return err
	}
	if s != nil {
		if err := s.Delete(); err != nil {
			return err
		}
	}
	restart = false
	return nil
}

func scheduleExecutableRemoval(path string) error {
	// Never schedule deletion of a reusable install path: a reinstall before
	// reboot could otherwise cause Windows to delete the new executable.
	retired := path + ".removed-" + secret(8) + ".exe"
	if err := os.Rename(path, retired); err != nil {
		return fmt.Errorf("Close HubMaster windows and retry removal: %w", err)
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(retired), nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

// A registered service can survive a removed or quarantined executable.
// Missing files are repaired from the installer; other read errors remain fatal.
func backupInstalledBinary(path string) (bool, error) {
	src, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer src.Close()
	backup, err := os.Create(path + ".backup")
	if err != nil {
		return false, err
	}
	_, copyErr := io.Copy(backup, src)
	if copyErr == nil {
		copyErr = backup.Sync()
	}
	err = errors.Join(copyErr, backup.Close())
	if err != nil {
		return false, err
	}
	return true, nil
}
