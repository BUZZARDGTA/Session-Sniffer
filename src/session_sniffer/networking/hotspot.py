"""Networking module for managing Windows Mobile Hotspot and Internet Connection Sharing (ICS).

Provides programmatic querying, starting, stopping, and credential configuration for
the Windows Mobile Hotspot via WinRT NetworkOperatorTetheringManager, as well as
Internet Connection Sharing (ICS) configuration via HNetCfg.HNetShare COM interfaces.
"""

import ctypes
import json
import logging
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Final, cast

from session_sniffer.networking.bridge_ics import get_adapter_classification
from session_sniffer.networking.interface import AllInterfaces
from session_sniffer.networking.manuf_lookup import MacLookup

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT_SECONDS: Final[float] = 12.0
MIN_SSID_LENGTH: Final[int] = 1
MAX_SSID_LENGTH: Final[int] = 32
MIN_PASSPHRASE_LENGTH: Final[int] = 8
MAX_PASSPHRASE_LENGTH: Final[int] = 63

_WINRT_HOTSPOT_INFO_SCRIPT: Final[str] = """
[Windows.System.UserProfile.LockScreen, Windows.System.UserProfile, ContentType = WindowsRuntime] | Out-Null
Add-Type -AssemblyName System.Runtime.WindowsRuntime

$netConn = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
$profile = $netConn::GetInternetConnectionProfile()
$tetheringType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
$mgr = $tetheringType::CreateFromConnectionProfile($profile)

if ($mgr) {
    $config = $mgr.GetCurrentAccessPointConfiguration()
    $clients = $mgr.GetTetheringClients()
    $clientList = @()
    if ($clients) {
        foreach ($client in $clients) {
            $hostnames = @()
            if ($client.HostNames) {
                foreach ($hostname in $client.HostNames) {
                    $hostnames += $hostname.CanonicalName
                }
            }
            $clientList += @{
                Mac = $client.MacAddress
                Hostnames = $hostnames
            }
        }
    }
    $info = @{
        Success = $true
        State = [string]$mgr.TetheringOperationalState
        ClientCount = $mgr.ClientCount
        MaxClients = $mgr.MaxClientCount
        Ssid = $config.Ssid
        Passphrase = $config.Passphrase
        Band = [string]$config.Band
        Clients = $clientList
    }
    Write-Output (ConvertTo-Json -Depth 5 $info)
} else {
    Write-Output '{"Success": false, "Error": "No internet connection profile available for tethering manager"}'
}
"""

_WINRT_CONFIGURE_HOTSPOT_SCRIPT: Final[str] = """
param([string]$NewSsid, [string]$NewPassphrase)

[Windows.System.UserProfile.LockScreen, Windows.System.UserProfile, ContentType = WindowsRuntime] | Out-Null
Add-Type -AssemblyName System.Runtime.WindowsRuntime

$extMethods = [System.WindowsRuntimeSystemExtensions].GetMethods()
$asActionGeneric = ($extMethods | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
})[0]

function Await-Action($action) {
    $task = $asActionGeneric.Invoke($null, @($action))
    $task.Wait(10000) | Out-Null
}

$netConn = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
$profile = $netConn::GetInternetConnectionProfile()
$tetheringType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
$mgr = $tetheringType::CreateFromConnectionProfile($profile)

if ($mgr) {
    $config = $mgr.GetCurrentAccessPointConfiguration()
    $config.Ssid = $NewSsid
    $config.Passphrase = $NewPassphrase
    $action = $mgr.ConfigureAccessPointAsync($config)
    Await-Action $action
    Write-Output '{"Success": true}'
} else {
    Write-Output '{"Success": false, "Error": "Unable to initialize tethering manager to save credentials"}'
}
"""

_WINRT_START_HOTSPOT_SCRIPT: Final[str] = """
[Windows.System.UserProfile.LockScreen, Windows.System.UserProfile, ContentType = WindowsRuntime] | Out-Null
Add-Type -AssemblyName System.Runtime.WindowsRuntime

$extMethods = [System.WindowsRuntimeSystemExtensions].GetMethods()
$asTaskGeneric = ($extMethods | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await-Op($op, $resultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($resultType)
    $task = $asTask.Invoke($null, @($op))
    $task.Wait(12000) | Out-Null
    return $task.Result
}

$netConn = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
$profile = $netConn::GetInternetConnectionProfile()
$tetheringType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
$mgr = $tetheringType::CreateFromConnectionProfile($profile)

if ($mgr) {
    $op = $mgr.StartTetheringAsync()
    $result = Await-Op $op ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
    if ($result) {
        $statusStr = [string]$result.Status
        $errStr = [string]$result.AdditionalErrorMessage
        Write-Output (ConvertTo-Json @{ Success = ($statusStr -eq 'Success'); Status = $statusStr; Error = $errStr })
    } else {
        Write-Output '{"Success": false, "Error": "Start operation timed out or returned no result"}'
    }
} else {
    Write-Output '{"Success": false, "Error": "No internet connection profile available to start mobile hotspot"}'
}
"""

_WINRT_STOP_HOTSPOT_SCRIPT: Final[str] = """
[Windows.System.UserProfile.LockScreen, Windows.System.UserProfile, ContentType = WindowsRuntime] | Out-Null
Add-Type -AssemblyName System.Runtime.WindowsRuntime

$extMethods = [System.WindowsRuntimeSystemExtensions].GetMethods()
$asTaskGeneric = ($extMethods | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await-Op($op, $resultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($resultType)
    $task = $asTask.Invoke($null, @($op))
    $task.Wait(12000) | Out-Null
    return $task.Result
}

$netConn = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
$profile = $netConn::GetInternetConnectionProfile()
$tetheringType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
$mgr = $tetheringType::CreateFromConnectionProfile($profile)

if ($mgr) {
    $op = $mgr.StopTetheringAsync()
    $result = Await-Op $op ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
    if ($result) {
        $statusStr = [string]$result.Status
        Write-Output (ConvertTo-Json @{ Success = ($statusStr -eq 'Success'); Status = $statusStr })
    } else {
        Write-Output '{"Success": false, "Error": "Stop operation timed out or returned no result"}'
    }
} else {
    Write-Output '{"Success": false, "Error": "No tethering manager available to stop"}'
}
"""

_ICS_ENABLE_SCRIPT: Final[str] = """
param([string]$PublicAdapterName, [string]$PrivateAdapterName)

try {
    $service = Get-Service -Name SharedAccess -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Running') {
        Set-Service -Name SharedAccess -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name SharedAccess -ErrorAction SilentlyContinue
    }

    $manager = New-Object -ComObject HNetCfg.HNetShare
    $connections = $manager.EnumEveryConnection

    $publicConnection = $null
    $privateConnection = $null

    foreach ($connection in $connections) {
        $props = $manager.NetConnectionProps.Invoke($connection)
        if ($props.Name -eq $PublicAdapterName) {
            $publicConnection = $connection
        }
        if ($props.Name -eq $PrivateAdapterName) {
            $privateConnection = $connection
        }
    }

    if (-not $publicConnection) {
        Write-Output (ConvertTo-Json @{ Success = $false; Error = "Public adapter '$PublicAdapterName' not found in network connections" })
        exit
    }
    if (-not $privateConnection) {
        Write-Output (ConvertTo-Json @{ Success = $false; Error = "Private adapter '$PrivateAdapterName' not found in network connections" })
        exit
    }

    # Disable sharing on all existing connections first
    foreach ($connection in $connections) {
        $config = $manager.INetSharingConfigurationForINetConnection.Invoke($connection)
        if ($config.SharingEnabled) {
            $config.DisableSharing()
        }
    }

    # Enable public connection (0 = public / internet source)
    $pubConfig = $manager.INetSharingConfigurationForINetConnection.Invoke($publicConnection)
    $pubConfig.EnableSharing(0)

    # Enable private connection (1 = private / local device)
    $privConfig = $manager.INetSharingConfigurationForINetConnection.Invoke($privateConnection)
    $privConfig.EnableSharing(1)

    Write-Output '{"Success": true}'
} catch {
    Write-Output (ConvertTo-Json @{ Success = $false; Error = $_.Exception.Message })
}
"""

_ICS_DISABLE_SCRIPT: Final[str] = """
try {
    $manager = New-Object -ComObject HNetCfg.HNetShare
    $connections = $manager.EnumEveryConnection
    foreach ($connection in $connections) {
        $config = $manager.INetSharingConfigurationForINetConnection.Invoke($connection)
        if ($config.SharingEnabled) {
            $config.DisableSharing()
        }
    }
    Write-Output '{"Success": true}'
} catch {
    Write-Output (ConvertTo-Json @{ Success = $false; Error = $_.Exception.Message })
}
"""


@dataclass(frozen=True, slots=True)
class HotspotInfo:
    """Snapshot of current Windows Mobile Hotspot state and configuration."""

    operational_state: str
    ssid: str
    passphrase: str
    band: str
    client_count: int
    max_clients: int


@dataclass(frozen=True, slots=True)
class ConnectedDevice:
    """Information regarding a device connected via Hotspot or connection sharing."""

    hostname: str
    ip_address: str
    mac_address: str
    vendor_name: str | None
    connection_type: str


def is_admin() -> bool:
    """Return whether the current process is running with administrative elevation."""
    if sys.platform == 'win32':
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except AttributeError, OSError:
            return False
    return False


def _run_powershell_script(script_text: str, *arguments: str) -> dict[str, object]:
    """Execute a PowerShell command string safely and return decoded JSON output."""
    if sys.platform != 'win32':
        return {'Success': False, 'Error': 'Hotspot and ICS management is only supported on Windows.'}

    command_args = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script_text]
    if arguments:
        command_args.extend(arguments)

    creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        with (
            tempfile.TemporaryFile(mode='w+', encoding='utf-8') as stdout_file,
            tempfile.TemporaryFile(mode='w+', encoding='utf-8') as stderr_file,
        ):
            subprocess.run(
                command_args,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=_SUBPROCESS_TIMEOUT_SECONDS,
                creationflags=creation_flags,
                check=False,
            )
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout_text = stdout_file.read().strip()
            stderr_text = stderr_file.read().strip()
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning('PowerShell script execution failed: %s', e)
        return {'Success': False, 'Error': str(e)}

    if not stdout_text:
        logger.warning('PowerShell returned empty stdout. Stderr: %s', stderr_text)
        return {'Success': False, 'Error': stderr_text or 'Empty output from PowerShell'}

    try:
        raw_decoded = cast('object', json.loads(stdout_text))
    except json.JSONDecodeError:
        logger.debug('Failed to decode JSON from PowerShell output: %s', stdout_text)
        return {'Success': False, 'RawOutput': stdout_text}

    if isinstance(raw_decoded, dict):
        return cast('dict[str, object]', raw_decoded)
    return {'Success': True, 'Data': raw_decoded}


def get_hotspot_info() -> HotspotInfo:
    """Retrieve the current Mobile Hotspot operational state and configuration."""
    response = _run_powershell_script(_WINRT_HOTSPOT_INFO_SCRIPT)
    if not response.get('Success', False):
        error_message = str(response.get('Error', 'Failed to query hotspot state'))
        logger.debug('Hotspot info query returned error: %s', error_message)
        return HotspotInfo(
            operational_state='Off',
            ssid='',
            passphrase='',
            band='',
            client_count=0,
            max_clients=8,
        )

    operational_state = str(response.get('State', 'Off'))
    ssid = str(response.get('Ssid', ''))
    passphrase = str(response.get('Passphrase', ''))
    band = str(response.get('Band', ''))
    client_count_val = response.get('ClientCount', 0)
    client_count = int(client_count_val) if isinstance(client_count_val, int | str) else 0
    max_clients_val = response.get('MaxClients', 8)
    max_clients = int(max_clients_val) if isinstance(max_clients_val, int | str) else 8

    return HotspotInfo(
        operational_state=operational_state,
        ssid=ssid,
        passphrase=passphrase,
        band=band,
        client_count=client_count,
        max_clients=max_clients,
    )


def configure_hotspot(ssid: str, passphrase: str) -> tuple[bool, str | None]:
    """Configure the Mobile Hotspot SSID and WPA2 passphrase.

    Args:
        ssid: Network SSID (1 to 32 characters).
        passphrase: Network password (8 to 63 characters).

    Returns:
        Tuple of (success_boolean, optional_error_message).
    """
    if len(ssid) < MIN_SSID_LENGTH or len(ssid) > MAX_SSID_LENGTH:
        return False, f'SSID must be between {MIN_SSID_LENGTH} and {MAX_SSID_LENGTH} characters.'
    if len(passphrase) < MIN_PASSPHRASE_LENGTH or len(passphrase) > MAX_PASSPHRASE_LENGTH:
        return False, f'Password must be between {MIN_PASSPHRASE_LENGTH} and {MAX_PASSPHRASE_LENGTH} characters.'

    # Escape parameters for PowerShell script call
    escaped_ssid = ssid.replace("'", "''")
    escaped_pass = passphrase.replace("'", "''")
    script = f"& {{ {_WINRT_CONFIGURE_HOTSPOT_SCRIPT} }} -NewSsid '{escaped_ssid}' -NewPassphrase '{escaped_pass}'"

    response = _run_powershell_script(script)
    if response.get('Success', False):
        return True, None

    error_message = str(response.get('Error', 'Failed to configure hotspot credentials'))
    return False, error_message


def start_hotspot() -> tuple[bool, str | None]:
    """Start the Windows Mobile Hotspot.

    Returns:
        Tuple of (success_boolean, optional_error_message).
    """
    response = _run_powershell_script(_WINRT_START_HOTSPOT_SCRIPT)
    if response.get('Success', False):
        return True, None

    error_message = str(response.get('Error', response.get('Status', 'Failed to start mobile hotspot')))
    return False, error_message


def stop_hotspot() -> tuple[bool, str | None]:
    """Stop the Windows Mobile Hotspot.

    Returns:
        Tuple of (success_boolean, optional_error_message).
    """
    response = _run_powershell_script(_WINRT_STOP_HOTSPOT_SCRIPT)
    if response.get('Success', False):
        return True, None

    error_message = str(response.get('Error', 'Failed to stop mobile hotspot'))
    return False, error_message


def _resolve_neighbour_info(mac_address: str) -> tuple[str, str | None]:
    """Find IP address and optional vendor name for a MAC from known interface neighbours."""
    target_mac = mac_address.upper()
    for interface in AllInterfaces.iterate():
        for neighbour in interface.neighbour_entries:
            if neighbour.mac_address and neighbour.mac_address.upper() == target_mac:
                return neighbour.ip_address, neighbour.vendor_name
    return '', None


def get_connected_devices() -> list[ConnectedDevice]:
    """Retrieve list of devices connected through Mobile Hotspot."""
    devices: list[ConnectedDevice] = []
    response = _run_powershell_script(_WINRT_HOTSPOT_INFO_SCRIPT)

    clients_data = response.get('Clients')
    if isinstance(clients_data, list):
        for raw_entry in cast('list[object]', clients_data):
            if not isinstance(raw_entry, dict):
                continue
            entry_dict = cast('dict[str, object]', raw_entry)
            mac_raw = str(entry_dict.get('Mac', ''))
            hostnames_raw = entry_dict.get('Hostnames')
            hostname = 'Unknown Device'
            if isinstance(hostnames_raw, list):
                raw_list = cast('list[object]', hostnames_raw)
                if raw_list and isinstance(raw_list[0], str):
                    hostname = raw_list[0]

            resolved_ip, neighbour_vendor = _resolve_neighbour_info(mac_raw) if mac_raw else ('', None)
            vendor_name = neighbour_vendor or (MacLookup.get_vendor_name(mac_raw) if mac_raw else None)

            devices.append(
                ConnectedDevice(
                    hostname=hostname,
                    ip_address=resolved_ip or 'Assigned via DHCP',
                    mac_address=mac_raw,
                    vendor_name=vendor_name,
                    connection_type='Wi-Fi Hotspot',
                )
            )

    return devices


def get_ics_status() -> tuple[bool, str | None, str | None]:
    """Return whether Internet Connection Sharing is active and the public/private adapters.

    Returns:
        Tuple of (is_sharing_active, public_adapter_name, private_adapter_name).
    """
    classifications = get_adapter_classification()
    public_adapter_name: str | None = None
    private_adapter_name: str | None = None

    for interface in AllInterfaces.iterate():
        guid = interface.identity.adapter_guid
        if not guid:
            continue
        classification = classifications.get(guid)
        if classification == 'sharing':
            public_adapter_name = interface.identity.name
        elif classification == 'shared':
            private_adapter_name = interface.identity.name

    is_active = bool(public_adapter_name and private_adapter_name)
    return is_active, public_adapter_name, private_adapter_name


def enable_ics(public_adapter_name: str, private_adapter_name: str) -> tuple[bool, str | None]:
    """Enable Windows Internet Connection Sharing (ICS).

    Args:
        public_adapter_name: Adapter connected to the internet/WAN/VPN.
        private_adapter_name: Adapter connected to the console or local target device.

    Returns:
        Tuple of (success_boolean, optional_error_message).
    """
    if not is_admin():
        return False, 'Administrator permissions are required to configure Windows Internet Connection Sharing. Please run Session Sniffer as administrator.'

    escaped_public = public_adapter_name.replace("'", "''")
    escaped_private = private_adapter_name.replace("'", "''")
    script = f"& {{ {_ICS_ENABLE_SCRIPT} }} -PublicAdapterName '{escaped_public}' -PrivateAdapterName '{escaped_private}'"

    response = _run_powershell_script(script)
    if response.get('Success', False):
        return True, None

    error_message = str(response.get('Error', 'Failed to configure Internet Connection Sharing'))
    return False, error_message


def disable_ics() -> tuple[bool, str | None]:
    """Disable Windows Internet Connection Sharing across all network adapters.

    Returns:
        Tuple of (success_boolean, optional_error_message).
    """
    if not is_admin():
        return False, 'Administrator permissions are required to modify Windows Internet Connection Sharing. Please run Session Sniffer as administrator.'

    response = _run_powershell_script(_ICS_DISABLE_SCRIPT)
    if response.get('Success', False):
        return True, None

    error_message = str(response.get('Error', 'Failed to disable Internet Connection Sharing'))
    return False, error_message
