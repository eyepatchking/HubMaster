# HubMaster Windows 2.3.2

- Hide menu now collapses the sidebar to a 68px rail (60px on small screens). Navigation, password, export, logout and network icons stay visible.
- Native tooltips and accessible names remain available when labels are hidden.
- Consistent local SVG icons added to navigation, password change/reset, export, scan, menu/activity controls, copy, back, close, save and device actions. No external icon/fonts dependency.
- Sidebar action spacing and small-screen layout improved. Reduced-motion preference is respected.
- Existing data/policies and installer repair from 2.3.1 are retained.
- Linux agent package remains 2.3.0; this is a Windows dashboard update.

Checks: JavaScript syntax and fixture-based expanded/collapsed menu behavior, saved selection and reset form rendering passed. No live browser screenshot test was available for this patch. Go/installer/scan outcomes are recorded separately.

Antivirus: no antivirus protection/exclusion changes or detection bypasses are included. No new VirusTotal upload was performed. Code signing still requires a real publisher certificate.
