"""GTA5-specific process detection and suspension control.

Groups the three modules dedicated to the single, globally-resolved GTA V process:

- `process`: detect the running GTA5 executable and snapshot its state (`GTA5Status`,
    `find_running_gta5_path`).
- `monitor`: background thread that polls the GTA5 PID and keeps `CaptureState` current
    (`ensure_gta5_process_monitor_running`).
- `suspend_manager`: reason-based suspend/resume of that process (`GTASuspendManager`).

Import symbols directly from their submodules
(e.g. `from session_sniffer.gta5.process import GTA5Status`). This keeps `process` a
dependency-light leaf and avoids pulling the monitor's or suspend manager's heavier
imports into call sites that only need detection.
"""
