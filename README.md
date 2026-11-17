# Windows 2.3.2 dashboard update

Hide menu preserves an icon-only navigation rail. See CHANGES-2.3.2.md.

# Windows 2.3.1 repair patch

Windows installers can now restore a missing Admin.exe or Agent.exe when the
service registration is still present. Existing binaries are still backed up;
access-denied and other I/O errors remain fatal. New regression tests cover
existing and missing binaries. Linux functionality remains at 2.3.0.

# HubMaster 2.3.0

HubMaster manages removable devices on a local network. The administrator
console runs on Windows; agents run on Windows and Debian/Ubuntu amd64.
Install the Admin setup on the administrator PC and Agent setup on clients.
Pair with a six-digit OTP (three-minute expiry, five attempts). Existing 2.2
installations can be upgraded in place without deleting policies or logs.

## Passwords and recovery

Use Change password in the signed-in sidebar. It requires the current password,
confirms the new one, rotates the recovery key and invalidates older sessions.
New passwords use 12–128 ASCII characters with upper/lowercase letters, a digit
and a symbol. Old configured passwords continue to work.

If the password is forgotten, use the recovery key on the login screen. If both
are lost, open HubMaster Admin Recovery from Windows Start, approve elevation
and confirm recovery. Alternatively launch Admin.exe --recover. The service
is stopped before recovery state changes. Policies, pairing, audit key and
history are retained. The elevated launcher opens a one-time setup page.
The OS administrator remains the authority over the local installation.

## Removal

Normally authorize agent removal in the Admin console, wait for it to finish,
then uninstall through Windows Installed apps. If the remote Admin is gone,
the elevated Agent uninstaller offers local administrator removal, releasing
HubMaster-owned device blocks before deleting the service. It retains audit
data. A warning appears before Admin removal while remote agents remain.
Self-removal first retires the running executable to a unique name, preventing
a queued reboot deletion from deleting a newly reinstalled executable.

On Linux authorize removal remotely, then sudo apt purge hubmaster-agent.
If Admin is unavailable, run sudo hubmaster-agent --remove-local first. That
command requires root and releases owned blocks before disabling the service.

## Dashboard

Uzbek, Russian and English; System/Light/Dark themes saved per browser.
Change password and Export audit are in the sidebar. Unsupported device
controls are labelled explicitly. Communication errors are shown as toasts.

## Audit and resource limits

TLS 1.3 with pinned certificates protects agent traffic. Passwords use PBKDF2;
agent tokens are hashed on the Admin. Audit records form an HMAC chain.
Audit writes update memory after durable file writes. An interrupted final
uncommitted fragment is preserved as a .partial file and reported as audit.gap;
modified complete records and missing committed history cause verification failure.

Active logs rotate at 16 MiB into audit.jsonl.archive-* and are verified in order
on startup. Export downloads active and archived records. The UI retains the
latest 10,000 events. The 256 MiB storage ceiling includes archived and partial
files; new audit writes are rejected at the ceiling to preserve evidence.
For maintenance, stop the services, back up the complete Admin directory, move
audit.jsonl, all audit.jsonl.archive-* files and audit-head.json together into
a protected backup, then restart. This starts a new audit chain; keep all
original files and AuditKey in the protected backup to verify older history.
Do not remove an individual archive from a running chain.

Offline events use at most 64 MiB on disk and 1,000 buffered events. Persisted
batches can drain at the limit. Corrupt batches are quarantined and reported.
Prolonged storage failure can lose excess events; counted losses are reported
as audit.gap after recovery. A crash can also lose not-yet-flushed memory events.
Heartbeats remain within the 2,048-device protocol limit, prioritizing present
devices. Unruled disconnected history is bounded, and device policies cap at
4,096 entries. Concurrent pairing requests are serialized.

## Linux support

The package depends on systemd and auditd. Mounted USB/SD/optical file changes
use inotify, with move cookies for rename pairing and restart after watcher
failure. auditd supplies executable/PID attribution using HubMaster-owned
hubmaster_v2 rules, staged checkpoints, bounded subprocess output and timeouts.
Unrelated audit rules are not removed. Immutable/disabled audit configuration
is reported as an error. Keep auditd active for process attribution.

USB interface authorization enforces supported USB policies. SD and optical
control uses only the mmcblk/sr driver's bind/unbind interfaces when available
and when the root disk is known to be different. Root disk sibling partitions
are excluded. Unknown/unsafe controls remain unavailable. Sysfs hub topology
reports USB ports; typec class entries report USB-C connectors when exposed.
Topology lanes and Type-C connectors may describe the same physical connector;
firmware does not expose a universal physical port mapping.

## Protection boundaries and verification

HID monitoring is polling based, includes generic USB HID, and preserves
previously trusted devices. It cannot guarantee blocking before the device's
first action. A kernel-level prevention guarantee requires a separately
designed and signed device-control driver. Hardware identifiers can be spoofed.

Windows tests and vet, Linux vet/cross-build and Linux test-binary compilation
are used for this release. Dark mode and the password dialog were inspected
in a separate temporary dashboard; installed user settings were not changed.
Windows elevation/installation, real multi-PC pairing, USB/SD/DVD enforcement
and Linux runtime/auditd integration require hardware acceptance tests.
See TEKSHIRUV-2.3.0.txt in the deliverables for actual build/scan results.

## Building and signing

Go 1.26+; optional Python 3 for python package.py on Windows. The included
build-windows.ps1 can build Windows installers without Python. Build outputs
retain Go symbols. Set HUBMASTER_SIGN_THUMBPRINT to a trusted code-signing
certificate in CurrentUser\My to sign Python-built embedded executables and
final Windows installers with SHA-256 and a timestamp. No certificate is included.
Defender is not disabled or excluded. A clean local scan is not a guarantee of
future detection results. Submit any false positive to Microsoft's official
software developer file-submission portal.

Auditd command references: https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8 and https://github.com/linux-audit/audit-userspace/blob/master/docs/ausearch.8 .
