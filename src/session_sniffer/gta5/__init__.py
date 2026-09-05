"""GTA5-specific process detection and suspension control.

Groups modules dedicated to the GTA V process:

- `process`: detect the running GTA5 executable and snapshot its state (`GTA5Status`,
    `find_running_gta5_path`).
- `suspend_manager`: reason-based suspend/resume of that process (`GTASuspendManager`).

Import symbols directly from their submodules
(e.g. `from session_sniffer.gta5.process import GTA5Status`). This keeps `process` a
dependency-light leaf and avoids pulling the suspend manager's heavier
imports into call sites that only need detection.
"""
