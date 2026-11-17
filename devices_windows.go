package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var cfg = windows.NewLazySystemDLL("cfgmgr32.dll")
var cmParent = cfg.NewProc("CM_Get_Parent")
var cmDisable = cfg.NewProc("CM_Disable_DevNode")
var cmEnable = cfg.NewProc("CM_Enable_DevNode")
var cmLocate = cfg.NewProc("CM_Locate_DevNodeW")

var hubGUID = guid("{f18a0e88-c30c-11d0-8815-00a0c906bed8}")
var diskGUID = guid("{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")

func guid(s string) windows.GUID {
	id, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return id
}

func replaceFile(from, to string) error {
	return windows.MoveFileEx(windows.StringToUTF16Ptr(from), windows.StringToUTF16Ptr(to), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func enableBroadcast(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
	})
	if err != nil {
		return err
	}
	return optionErr
}

type pnpNode struct {
	instance, name, class, service, location, hardware string
	address, capabilities                              uint32
	parent                                             windows.DEVINST
	problem                                            uint32
}

func pnpSnapshot() (map[windows.DEVINST]pnpNode, error) {
	info, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return nil, err
	}
	defer windows.SetupDiDestroyDeviceInfoList(info)
	nodes := map[windows.DEVINST]pnpNode{}
	for i := 0; ; i++ {
		d, err := windows.SetupDiEnumDeviceInfo(info, i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			break
		}
		if err != nil {
			return nil, err
		}
		instance, err := windows.SetupDiGetDeviceInstanceId(info, d)
		if err != nil || instance == "" {
			continue
		}
		prop := func(p windows.SPDRP) any {
			v, _ := windows.SetupDiGetDeviceRegistryProperty(info, d, p)
			return v
		}
		str := func(p windows.SPDRP) string { v, _ := prop(p).(string); return v }
		num := func(p windows.SPDRP) uint32 { v, _ := prop(p).(uint32); return v }
		n := pnpNode{instance: strings.ToUpper(instance), name: str(windows.SPDRP_FRIENDLYNAME), class: str(windows.SPDRP_CLASS), service: str(windows.SPDRP_SERVICE), address: num(windows.SPDRP_ADDRESS), capabilities: num(windows.SPDRP_CAPABILITIES)}
		if n.name == "" {
			n.name = str(windows.SPDRP_DEVICEDESC)
		}
		locations, _ := prop(windows.SPDRP_LOCATION_PATHS).([]string)
		if len(locations) > 0 {
			n.location = locations[0]
		}
		if n.location == "" {
			n.location = str(windows.SPDRP_LOCATION_INFORMATION)
		}
		hardware, _ := prop(windows.SPDRP_HARDWAREID).([]string)
		if len(hardware) > 0 {
			n.hardware = hardware[0]
		}
		cmParent.Call(uintptr(unsafe.Pointer(&n.parent)), uintptr(d.DevInst), 0)
		var status uint32
		_ = windows.CM_Get_DevNode_Status(&status, &n.problem, d.DevInst, 0)
		nodes[d.DevInst] = n
	}
	return nodes, nil
}

func usbDevice(n pnpNode) bool {
	return strings.HasPrefix(n.instance, `USB\VID_`) && !strings.Contains(strings.Split(n.instance, `\`)[1], "&MI_")
}

func usbHub(n pnpNode) bool {
	service := strings.ToUpper(n.service)
	return service == "USBHUB3" || service == "USBHUB" || strings.HasPrefix(n.instance, `USB\ROOT_HUB`)
}

func usbAncestor(n pnpNode, nodes map[windows.DEVINST]pnpNode) (pnpNode, bool) {
	for i := 0; i < 32; i++ {
		if usbDevice(n) && !usbHub(n) {
			return n, true
		}
		parent, ok := nodes[n.parent]
		if !ok {
			break
		}
		n = parent
	}
	return pnpNode{}, false
}

func deviceKind(n pnpNode, usb bool) string {
	switch strings.ToLower(n.class) {
	case "keyboard":
		if usb {
			return "keyboard"
		}
	case "mouse":
		if usb {
			return "mouse"
		}
	case "hidclass":
		if usb {
			return "hid"
		}
	case "printer", "printqueue":
		if usb {
			return "printer"
		}
	case "diskdrive":
		if usb || strings.HasPrefix(n.instance, `USBSTOR\`) {
			return "storage"
		}
		if strings.HasPrefix(n.instance, `SD\`) || strings.HasPrefix(n.instance, `SDSTOR\`) {
			return "sd"
		}
	case "cdrom":
		return "optical"
	case "sdhost", "memorytechnology", "sd":
		return "sdreader"
	case "wpd":
		if usb {
			return "portable"
		}
	default:
		if usb && usbDevice(n) && !strings.EqualFold(n.service, "USBCCGP") &&
			!strings.EqualFold(n.service, "USBSTOR") && !strings.EqualFold(n.service, "UASPStor") {
			return "usb"
		}
	}
	return ""
}

func windowsDeviceIdentity(n, root pnpNode, kind string) (string, string, string) {
	parts := strings.Split(root.instance, `\`)
	serial := ""
	if len(parts) == 3 && root.capabilities&0x10 != 0 {
		serial = parts[2]
	}
	identity := "instance"
	input := n.instance
	if serial != "" {
		identity = "serial"
		input = strings.Join([]string{parts[1], serial, kind, n.hardware}, "|")
	}
	return fingerprint([]byte(input))[:32], serial, identity
}

func scanDevices(includePorts bool) ([]attachedDevice, []Port, error) {
	nodes, err := pnpSnapshot()
	if err != nil {
		return nil, nil, err
	}
	devicePort := map[string]string{}
	var ports []Port
	if includePorts {
		ports, devicePort = scanPorts(nodes)
	}
	systemDisk, systemKnown := diskNumber(`\\.\` + os.Getenv("SystemDrive"))
	disks := map[uint32]bool{}
	rootDiskCount := map[string]int{}
	unsafeRoots := map[string]bool{}
	for _, n := range nodes {
		if !strings.EqualFold(n.class, "DiskDrive") {
			continue
		}
		ancestor, usb := usbAncestor(n, nodes)
		if !usb && !strings.HasPrefix(n.instance, `SD`) {
			continue
		}
		if usb {
			rootDiskCount[ancestor.instance]++
		}
		paths, _ := windows.CM_Get_Device_Interface_List(n.instance, &diskGUID, 0)
		safe := false
		for _, path := range paths {
			if num, ok := diskNumber(path); ok && systemKnown && num != systemDisk {
				disks[num] = true
				safe = true
			}
		}
		if usb && !safe {
			unsafeRoots[ancestor.instance] = true
		}
	}
	result := make([]attachedDevice, 0)
	for _, n := range nodes {
		root, usb := usbAncestor(n, nodes)
		if strings.EqualFold(n.class, "Bluetooth") || strings.Contains(strings.ToLower(n.name), "bluetooth") || strings.Contains(strings.ToLower(root.name), "bluetooth") {
			continue
		}
		kind := deviceKind(n, usb)
		if kind == "" {
			continue
		}
		if !usb {
			root = n
		}
		hardware := root.hardware
		id, serial, identity := windowsDeviceIdentity(n, root, kind)
		port := devicePort[root.instance]
		controllable := kind == "storage" || kind == "sd" || kind == "optical" || kind == "keyboard" || kind == "mouse" || kind == "hid" || kind == "printer" || kind == "portable"
		if kind == "storage" || kind == "sd" {
			controllable = false
			paths, _ := windows.CM_Get_Device_Interface_List(n.instance, &diskGUID, 0)
			for _, path := range paths {
				if num, ok := diskNumber(path); ok && disks[num] {
					controllable = true
				}
			}
		}
		instance := n.instance
		if kind == "storage" && usb && controllable && root.capabilities&0x10 != 0 && rootDiskCount[root.instance] == 1 && !unsafeRoots[root.instance] {
			// Disabling the removable USB device removes the disk stack from
			// Windows, including an already mounted volume. UniqueID keeps
			// the rule tied to this device across ports.
			instance = root.instance
		}
		// A disabled device has no live disk interface. Only our own disabled
		// instances are re-enabled by the policy engine.
		risky := usb && (kind == "keyboard" || kind == "mouse" || kind == "hid")
		name := n.name
		if name == "" {
			name = n.instance
		}
		result = append(result, attachedDevice{Device: Device{ID: id, Name: name, Kind: kind, Port: port, Serial: serial, Hardware: hardware, Identity: identity, Blocked: n.problem == 22 || instance == root.instance && root.problem == 22, Present: true, Controllable: controllable, Risky: risky}, Instance: instance})
		if (kind == "optical" || kind == "sdreader" || (kind == "sd" && !usb)) && includePorts {
			ports = append(ports, Port{ID: id, Name: name, Kind: kind, Connected: kind != "sdreader"})
		}
	}
	slices.SortFunc(result, func(a, b attachedDevice) int { return strings.Compare(a.Name+a.ID, b.Name+b.ID) })
	slices.SortFunc(ports, func(a, b Port) int { return strings.Compare(a.Name, b.Name) })
	return result, ports, nil
}

func openDevice(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
}

func ioctl(h windows.Handle, code uint32, in, out []byte) (uint32, error) {
	var input, output *byte
	if len(in) > 0 {
		input = &in[0]
	}
	if len(out) > 0 {
		output = &out[0]
	}
	var written uint32
	err := windows.DeviceIoControl(h, code, input, uint32(len(in)), output, uint32(len(out)), &written, nil)
	return written, err
}

func diskNumber(path string) (uint32, bool) {
	h, err := openDevice(path, 0)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(h)
	return handleDiskNumber(h)
}

func handleDiskNumber(h windows.Handle) (uint32, bool) {
	var out [12]byte
	n, err := ioctl(h, 0x002d1080, nil, out[:]) // IOCTL_STORAGE_GET_DEVICE_NUMBER
	return binary.LittleEndian.Uint32(out[4:]), err == nil && n >= 12
}

func setDevice(instance string, block bool) error {
	var dev windows.DEVINST
	id, err := windows.UTF16PtrFromString(instance)
	if err != nil {
		return err
	}
	locateFlags := uintptr(0)
	if !block {
		locateFlags = 1
	} // also locate a non-present node to undo a persistent disable
	result, _, _ := cmLocate.Call(uintptr(unsafe.Pointer(&dev)), uintptr(unsafe.Pointer(id)), locateFlags)
	if result != 0 {
		return fmt.Errorf("CM_Locate_DevNode 0x%x", result)
	}
	if block {
		result, _, _ = cmDisable.Call(uintptr(dev), 0x4|0x8)
	} else {
		result, _, _ = cmEnable.Call(uintptr(dev), 0)
	}
	if result != 0 {
		return fmt.Errorf("Configuration Manager 0x%x", result)
	}
	return nil
}

type hubPort struct {
	Port
	companion []string
}

func hubKey(path string, index uint32) string {
	path = strings.ToUpper(path)
	path = strings.TrimPrefix(path, `\\?\`)
	path = strings.TrimPrefix(path, `\??\`)
	return path + "/" + strconv.FormatUint(uint64(index), 10)
}

func scanPorts(nodes map[windows.DEVINST]pnpNode) ([]Port, map[string]string) {
	found := map[string]hubPort{}
	attached := map[string]string{}
	hubs := map[windows.DEVINST]string{}
	for handle, node := range nodes {
		if !usbHub(node) {
			continue
		}
		paths, _ := windows.CM_Get_Device_Interface_List(node.instance, &hubGUID, 0)
		for _, path := range paths {
			h, err := openDevice(path, windows.GENERIC_WRITE)
			if err != nil {
				continue
			}
			hubs[handle] = path
			var info [1024]byte
			_, err = ioctl(h, 0x00220408, info[:], info[:]) // IOCTL_USB_GET_NODE_INFORMATION
			if err == nil {
				for i := uint32(1); i <= uint32(info[6]); i++ {
					k := hubKey(path, i)
					p := hubPort{Port: Port{ID: fingerprint([]byte(k))[:16], Name: fmt.Sprintf("USB · %s · %d", fingerprint([]byte(path))[:4], i), Kind: "usb"}}
					visible := true
					for companionIndex := uint16(0); companionIndex < 4; companionIndex++ {
						var props [2048]byte
						binary.LittleEndian.PutUint32(props[:], i)
						binary.LittleEndian.PutUint16(props[12:], companionIndex)
						size, err := ioctl(h, 0x00220458, props[:], props[:]) // IOCTL_USB_GET_PORT_CONNECTOR_PROPERTIES
						if err != nil || size < 18 {
							break
						}
						flags := binary.LittleEndian.Uint32(props[8:])
						visible = flags&1 != 0
						if flags&8 != 0 {
							p.Kind = "usb_c"
						}
						other := binary.LittleEndian.Uint16(props[14:])
						name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&props[16])))
						if other > 0 && name != "" {
							p.companion = append(p.companion, hubKey(name, uint32(other)))
						}
						if flags&4 == 0 || other == 0 {
							break
						}
					}
					if visible {
						found[k] = p
					}
				}
			}
			windows.CloseHandle(h)
		}
	}
	for _, n := range nodes {
		path := hubs[n.parent]
		if path == "" || n.address == 0 {
			continue
		}
		k := hubKey(path, n.address)
		if p, ok := found[k]; ok {
			p.Connected = true
			found[k] = p
			attached[n.instance] = k
		}
	}
	keys := make([]string, 0, len(found))
	for key := range found {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	representative := map[string]string{}
	ports := []Port{}
	for _, key := range keys {
		if representative[key] != "" {
			continue
		}
		p := found[key]
		members := []string{key}
		for _, other := range p.companion {
			if q, ok := found[other]; ok && representative[other] == "" {
				if q.Kind == "usb_c" {
					p.Kind = "usb_c"
				}
				p.Connected = p.Connected || q.Connected
				members = append(members, other)
			}
		}
		label := "USB port"
		if p.Kind == "usb_c" {
			label = "USB-C port"
		}
		p.Name = fmt.Sprintf("%s %d", label, len(ports)+1)
		for _, member := range members {
			representative[member] = p.Name
		}
		ports = append(ports, p.Port)
	}
	for instance, key := range attached {
		attached[instance] = representative[key]
	}
	return ports, attached
}
