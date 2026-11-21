"""Windows Defender Firewall status inspection and scoped inbound rule management for the embedded web server."""

import logging
import os
import sys
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address, IPv4Network, NetmaskValueError
from typing import TYPE_CHECKING, Final, Literal

if sys.platform == 'win32':
    import winreg

from session_sniffer.capture.process import get_process_image_path
from session_sniffer.ctypes_windows import (
    NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC,
    get_active_windows_firewall_profiles,
    get_system32_dir,
)
from session_sniffer.i18n import tr
from session_sniffer.utils import run_elevated_powershell_command

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

WEBSERVER_FIREWALL_RULE_NAME: Final[str] = 'Session Sniffer Web Server'
_WEBSERVER_FIREWALL_RULE_DESCRIPTION: Final[str] = 'Allows local network devices to access the Session Sniffer embedded web server.'

FirewallStatus = Literal['not_applicable', 'allowed', 'blocked', 'explicitly_blocked', 'block_all_inbound']

_LOCAL_FIREWALL_POLICY_KEY: Final[str] = r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
_GROUP_POLICY_FIREWALL_KEY: Final[str] = r'SOFTWARE\Policies\Microsoft\WindowsFirewall'
_RULE_STORE_SUBKEYS: Final[tuple[str, ...]] = (
    rf'{_LOCAL_FIREWALL_POLICY_KEY}\FirewallRules',
    rf'{_GROUP_POLICY_FIREWALL_KEY}\FirewallRules',
)
_PROFILE_REGISTRY_SUBKEYS: Final[dict[str, str]] = {
    'Domain': 'DomainProfile',
    'Private': 'StandardProfile',
    'Public': 'PublicProfile',
}
_ALL_PROFILE_NAMES: Final[frozenset[str]] = frozenset(_PROFILE_REGISTRY_SUBKEYS)
_FALLBACK_ACTIVE_PROFILES: Final[tuple[str, ...]] = ('Private', 'Public')
_PROFILE_TOKEN_MAP: Final[dict[str, frozenset[str]]] = {
    'domain': frozenset({'Domain'}),
    'private': frozenset({'Private'}),
    'public': frozenset({'Public'}),
    'any': _ALL_PROFILE_NAMES,
    'all': _ALL_PROFILE_NAMES,
}
_ANY_TOKENS: Final[frozenset[str]] = frozenset({'*', 'any'})
_LOCAL_SUBNET_TOKENS: Final[frozenset[str]] = frozenset({'*', 'any', 'localsubnet', 'localsubnet4', 'intranet'})
_TCP_PROTOCOL_TOKENS: Final[frozenset[str]] = frozenset({'6', 'tcp', 'any', '*'})
_IPV4_ANY_START: Final[IPv4Address] = IPv4Address('0.0.0.0')  # noqa: S104
_IPV4_ANY_END: Final[IPv4Address] = IPv4Address('255.255.255.255')
_MIN_TCP_PORT: Final[int] = 1
_MAX_TCP_PORT: Final[int] = 65535
_MAX_BROAD_PRIVATE_PREFIX: Final[int] = 24
_MIN_BROAD_PRIVATE_SPAN: Final[int] = 253


@dataclass(frozen=True, slots=True)
class _FirewallEvaluationContext:
    """Inputs needed to evaluate parsed Windows Defender Firewall rules for an inbound LAN TCP port."""

    enabled_profiles: frozenset[str]
    default_block_profiles: frozenset[str]
    port: int
    normalized_exe_path: str | None
    target_ip: IPv4Address | None


def _get_current_executable_path() -> str | None:
    """Return the OS process image path matched by Windows Firewall (resolving venv stubs to the real interpreter)."""
    image_path = get_process_image_path(os.getpid())
    if image_path is not None:
        return str(image_path)
    base_executable = getattr(sys, '_base_executable', None)
    if isinstance(base_executable, str) and base_executable:
        return base_executable
    return sys.executable or None


def _normalize_windows_path(raw_path: str) -> str:
    """Normalize a Windows executable path for case-insensitive comparison against firewall `App=` values."""
    expanded = os.path.expandvars(raw_path.strip().strip('"'))
    return os.path.normcase(os.path.normpath(expanded))


def _parse_optional_ipv4(ip_address: str | None) -> IPv4Address | None:
    """Parse *ip_address* into an `IPv4Address`, returning `None` when absent or invalid."""
    if ip_address is None or not ip_address:
        return None
    try:
        return IPv4Address(ip_address.strip())
    except AddressValueError:
        return None


def _parse_ipv4_network(token: str) -> IPv4Network | None:
    """Parse a CIDR or IP/netmask token into an `IPv4Network`, returning `None` on invalid input."""
    try:
        return IPv4Network(token, strict=False)
    except AddressValueError, NetmaskValueError:
        return None


def _parse_ipv4_range(token: str) -> tuple[IPv4Address, IPv4Address] | None:
    """Parse a `start-end` IPv4 range token, returning `None` on invalid input."""
    start_text, end_text = token.split('-', 1)
    try:
        return IPv4Address(start_text.strip()), IPv4Address(end_text.strip())
    except AddressValueError:
        return None


def _parse_firewall_rule(raw_rule: str) -> dict[str, list[str]]:
    """Parse a Windows Defender Firewall registry rule string (`v2.33|Key=Value|...`) into multi-valued fields."""
    fields: dict[str, list[str]] = {}
    for segment in raw_rule.split('|'):
        if '=' not in segment:
            continue
        key, value = segment.split('=', 1)
        if key:
            fields.setdefault(key, []).append(value)
    return fields


def _read_profile_dword(profile_subkey: str, value_name: str, default: int) -> int:
    """Read a DWORD value from a Windows Firewall profile registry key, honoring Group Policy overrides first."""
    if sys.platform == 'win32':
        for root_key in (_GROUP_POLICY_FIREWALL_KEY, _LOCAL_FIREWALL_POLICY_KEY):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf'{root_key}\{profile_subkey}', 0, winreg.KEY_READ) as key:
                    raw_value, _ = winreg.QueryValueEx(key, value_name)
                    if isinstance(raw_value, int):
                        return raw_value
            except OSError:
                continue
    return default


def _read_windows_firewall_rules() -> list[dict[str, list[str]]]:
    """Read parsed rule field dictionaries from the local and Group Policy Windows Firewall registry stores."""
    rules: list[dict[str, list[str]]] = []
    if sys.platform == 'win32':
        for store_subkey in _RULE_STORE_SUBKEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, store_subkey, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            _name, raw_value, _value_type = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        index += 1
                        if isinstance(raw_value, str) and raw_value:
                            rules.append(_parse_firewall_rule(raw_value))
            except OSError:
                continue
    return rules


def _get_active_profile_names() -> tuple[str, ...]:
    """Return currently active Windows Firewall profile names, falling back to Private + Public when unavailable."""
    mask = get_active_windows_firewall_profiles()
    active: list[str] = []
    if mask & NET_FW_PROFILE2_DOMAIN:
        active.append('Domain')
    if mask & NET_FW_PROFILE2_PRIVATE:
        active.append('Private')
    if mask & NET_FW_PROFILE2_PUBLIC:
        active.append('Public')
    return tuple(active) if active else _FALLBACK_ACTIVE_PROFILES


def _collect_prefixed_values(fields: dict[str, list[str]], exact_key: str, version_prefix: str) -> list[str]:
    """Return all rule field values for *exact_key* and any versioned sibling keys starting with *version_prefix*."""
    collected: list[str] = []
    for key, values in fields.items():
        if key == exact_key or key.startswith(version_prefix):
            collected.extend(values)
    return collected


def _rule_profiles(fields: dict[str, list[str]]) -> set[str]:
    """Return the set of firewall profiles (`Domain`, `Private`, `Public`) covered by a parsed rule."""
    raw_profiles = fields.get('Profile', ())
    if not raw_profiles:
        return set(_ALL_PROFILE_NAMES)
    matched: set[str] = set()
    for token in raw_profiles:
        matched.update(_PROFILE_TOKEN_MAP.get(token.strip().casefold(), ()))
    return matched


def _rule_matches_tcp_protocol(fields: dict[str, list[str]]) -> bool:
    """Return True when the rule applies to TCP (protocol 6) or all protocols."""
    protocols = fields.get('Protocol', ())
    if not protocols:
        return True
    return any(token.strip().casefold() in _TCP_PROTOCOL_TOKENS for token in protocols)


def _port_spec_matches(spec: str, port: int) -> bool:
    """Return True when a Windows Firewall `LPort` token (single port, range, or wildcard) covers *port*."""
    normalized = spec.strip().casefold()
    if normalized in _ANY_TOKENS:
        return True
    if '-' in normalized:
        start_text, end_text = normalized.split('-', 1)
        try:
            start_port = int(start_text)
            end_port = int(end_text)
        except ValueError:
            return False
        return start_port <= port <= end_port
    try:
        return int(normalized) == port
    except ValueError:
        return False


def _rule_matches_local_port(fields: dict[str, list[str]], port: int) -> bool:
    """Return True when the rule's local port criteria (`LPort`, `LPort2_*`) match *port*."""
    local_ports = _collect_prefixed_values(fields, 'LPort', 'LPort2_')
    if not local_ports:
        return True
    return any(_port_spec_matches(spec, port) for spec in local_ports)


def _rule_allows_ephemeral_remote_port(fields: dict[str, list[str]]) -> bool:
    """Return True when the rule does not restrict remote source ports away from ephemeral browser ports."""
    remote_ports = _collect_prefixed_values(fields, 'RPort', 'RPort2_')
    if not remote_ports:
        return True
    return any(token.strip().casefold() in _ANY_TOKENS for token in remote_ports)


def _ipv4_network_covers_local_network(token: str, target_ip: IPv4Address | None) -> bool:
    """Return True when a CIDR/netmask token covers *target_ip* or a broad private LAN."""
    network = _parse_ipv4_network(token)
    if network is None:
        return False
    if not network.prefixlen:
        return True
    return (target_ip in network) if target_ip is not None else (network.is_private and network.prefixlen <= _MAX_BROAD_PRIVATE_PREFIX)


def _ipv4_range_covers_local_network(token: str, target_ip: IPv4Address | None) -> bool:
    """Return True when an IPv4 `start-end` range token covers *target_ip* or a broad private LAN."""
    ip_range = _parse_ipv4_range(token)
    if ip_range is None:
        return False
    start_ip, end_ip = ip_range
    if start_ip == _IPV4_ANY_START and end_ip == _IPV4_ANY_END:
        return True
    if target_ip is not None:
        return start_ip <= target_ip <= end_ip
    return start_ip.is_private and end_ip.is_private and (int(end_ip) - int(start_ip)) >= _MIN_BROAD_PRIVATE_SPAN


def _ipv4_token_covers_local_network(token: str, target_ip: IPv4Address | None) -> bool:
    """Return True when a remote IPv4 (`RA4`) criterion permits devices on the local LAN subnet."""
    normalized = token.strip().casefold()
    if normalized in _LOCAL_SUBNET_TOKENS:
        return True
    if '/' in normalized:
        return _ipv4_network_covers_local_network(normalized, target_ip)
    if '-' in normalized:
        return _ipv4_range_covers_local_network(normalized, target_ip)
    return False


def _rule_matches_remote_ipv4(fields: dict[str, list[str]], target_ip: IPv4Address | None) -> bool:
    """Return True when the rule's remote IPv4 address criteria (`RA4`, `RA42*`) cover the local network."""
    remote_addrs = _collect_prefixed_values(fields, 'RA4', 'RA42')
    if not remote_addrs:
        return True
    return any(_ipv4_token_covers_local_network(token, target_ip) for token in remote_addrs)


def _local_ipv4_token_matches(token: str, target_ip: IPv4Address | None) -> bool:
    """Return True when a local IPv4 (`LA4`) criterion applies to the server's LAN address."""
    normalized = token.strip().casefold()
    if normalized in _LOCAL_SUBNET_TOKENS:
        return True
    if '/' in normalized:
        network = _parse_ipv4_network(normalized)
        return network is not None and ((target_ip in network) if target_ip is not None else not network.is_loopback)
    if '-' in normalized:
        ip_range = _parse_ipv4_range(normalized)
        if ip_range is None:
            return False
        start_ip, end_ip = ip_range
        return (start_ip <= target_ip <= end_ip) if target_ip is not None else not (start_ip.is_loopback and end_ip.is_loopback)
    parsed_ip = _parse_optional_ipv4(normalized)
    return parsed_ip is not None and ((parsed_ip == target_ip) if target_ip is not None else not parsed_ip.is_loopback)


def _rule_matches_local_ipv4(fields: dict[str, list[str]], target_ip: IPv4Address | None) -> bool:
    """Return True when the rule's local IPv4 address criteria (`LA4`, `LA42*`) match the server address."""
    local_addrs = _collect_prefixed_values(fields, 'LA4', 'LA42')
    if not local_addrs:
        return True
    return any(_local_ipv4_token_matches(token, target_ip) for token in local_addrs)


def _rule_matches_app(fields: dict[str, list[str]], normalized_exe_path: str | None) -> bool:
    """Return True when the rule targets any program or specifically matches the current executable."""
    services = fields.get('Svc', ())
    if services and not any(svc.strip().casefold() in _ANY_TOKENS for svc in services):
        return False
    if 'PFN' in fields:
        return False
    apps = fields.get('App', ())
    if not apps:
        return True
    if normalized_exe_path is None:
        return False
    return any(_normalize_windows_path(app) == normalized_exe_path for app in apps)


def _evaluate_windows_firewall_rules(
    rules: Iterable[dict[str, list[str]]],
    context: _FirewallEvaluationContext,
) -> FirewallStatus:
    """Evaluate parsed Windows Firewall rules against *context* and return the effective inbound status."""
    allowed_profiles: set[str] = set()
    explicitly_blocked_profiles: set[str] = set()

    for fields in rules:
        if not any(val.strip().casefold() == 'true' for val in fields.get('Active', ())):
            continue
        if not any(val.strip().casefold() == 'in' for val in fields.get('Dir', ())):
            continue

        actions = {val.strip().casefold() for val in fields.get('Action', ())}
        is_allow = 'allow' in actions
        is_block = 'block' in actions
        if not (is_allow or is_block):
            continue
        if is_allow and not is_block and 'LUAuth' in fields:
            continue

        matched_profiles = _rule_profiles(fields) & context.enabled_profiles
        if not matched_profiles:
            continue
        if not _rule_matches_tcp_protocol(fields):
            continue
        if not _rule_matches_app(fields, context.normalized_exe_path):
            continue
        if not _rule_matches_local_port(fields, context.port):
            continue
        if not _rule_allows_ephemeral_remote_port(fields):
            continue
        if not _rule_matches_remote_ipv4(fields, context.target_ip):
            continue
        if not _rule_matches_local_ipv4(fields, context.target_ip):
            continue

        if is_block:
            explicitly_blocked_profiles.update(matched_profiles)
        else:
            allowed_profiles.update(matched_profiles)

    if explicitly_blocked_profiles:
        return 'explicitly_blocked'
    if context.default_block_profiles - allowed_profiles:
        return 'blocked'
    return 'allowed'


def check_windows_firewall_status(port: int, *, local_ip: str | None = None) -> FirewallStatus:
    """Check whether Windows Defender Firewall permits inbound local-network TCP traffic to this process on *port*."""
    if sys.platform != 'win32' or port < _MIN_TCP_PORT or port > _MAX_TCP_PORT:
        return 'not_applicable'

    active_profiles = _get_active_profile_names()
    enabled_profiles: set[str] = set()
    default_block_profiles: set[str] = set()

    for profile_name in active_profiles:
        profile_subkey = _PROFILE_REGISTRY_SUBKEYS[profile_name]
        if not _read_profile_dword(profile_subkey, 'EnableFirewall', default=1):
            continue
        enabled_profiles.add(profile_name)
        if _read_profile_dword(profile_subkey, 'DoNotAllowExceptions', default=0):
            return 'block_all_inbound'
        if _read_profile_dword(profile_subkey, 'DefaultInboundAction', default=1):
            default_block_profiles.add(profile_name)

    if not enabled_profiles:
        return 'allowed'

    exe_path = _get_current_executable_path()
    normalized_exe_path = _normalize_windows_path(exe_path) if exe_path is not None else None
    context = _FirewallEvaluationContext(
        enabled_profiles=frozenset(enabled_profiles),
        default_block_profiles=frozenset(default_block_profiles),
        port=port,
        normalized_exe_path=normalized_exe_path,
        target_ip=_parse_optional_ipv4(local_ip),
    )
    return _evaluate_windows_firewall_rules(_read_windows_firewall_rules(), context)


def has_managed_webserver_firewall_rule() -> bool:
    """Return True if a Windows Defender Firewall rule managed by Session Sniffer (`Session Sniffer Web Server`) exists."""
    if sys.platform != 'win32':
        return False
    target_name = WEBSERVER_FIREWALL_RULE_NAME.casefold()
    return any(
        any(rule_name.strip().casefold() == target_name for rule_name in fields.get('Name', ()))
        for fields in _read_windows_firewall_rules()
    )


def _ps_single_quote(value: str) -> str:
    """Wrap *value* in a literal PowerShell single-quoted string."""
    return "'" + value.replace("'", "''") + "'"


def allow_webserver_firewall_port(port: int, *, local_ip: str | None = None) -> bool:
    """Create or update a scoped Windows Firewall inbound LAN rule for this process on TCP *port*."""
    if sys.platform != 'win32' or port < _MIN_TCP_PORT or port > _MAX_TCP_PORT:
        return False

    exe_path = _get_current_executable_path()
    if exe_path is None or any(ch in exe_path for ch in ('"', '\n', '\r')):
        logger.warning('Cannot create Windows Firewall rule: invalid executable path')
        return False

    netsh_exe = get_system32_dir() / 'netsh.exe'
    if not netsh_exe.is_file():
        logger.warning('Cannot create Windows Firewall rule: netsh.exe not found')
        return False

    netsh_arg = _ps_single_quote(str(netsh_exe))
    name_arg = _ps_single_quote(f'name={WEBSERVER_FIREWALL_RULE_NAME}')
    desc_arg = _ps_single_quote(f'description={_WEBSERVER_FIREWALL_RULE_DESCRIPTION}')
    port_arg = _ps_single_quote(f'localport={port}')
    program_arg = _ps_single_quote(f'program={exe_path}')

    ps_command = (
        f'& {netsh_arg} advfirewall firewall delete rule {name_arg} | Out-Null; '
        f'& {netsh_arg} advfirewall firewall add rule {name_arg} '
        f'dir=in action=allow protocol=tcp {port_arg} remoteip=localsubnet '
        f'{program_arg} profile=any enable=yes {desc_arg} | Out-Null'
    )
    if not run_elevated_powershell_command(ps_command):
        logger.warning('Windows Firewall rule update for web server port %d was declined or failed', port)
        return False

    allowed = check_windows_firewall_status(port, local_ip=local_ip) == 'allowed'
    if allowed:
        logger.info('Configured Windows Firewall inbound local-network rule for web server port %d', port)
    else:
        logger.warning('Windows Firewall still reports web server port %d as blocked after rule update', port)
    return allowed


def remove_webserver_firewall_rule() -> bool:
    """Remove the managed Session Sniffer Web Server Windows Firewall rule if present."""
    if sys.platform != 'win32':
        return False
    if not has_managed_webserver_firewall_rule():
        return True

    netsh_exe = get_system32_dir() / 'netsh.exe'
    if not netsh_exe.is_file():
        return False

    netsh_arg = _ps_single_quote(str(netsh_exe))
    name_arg = _ps_single_quote(f'name={WEBSERVER_FIREWALL_RULE_NAME}')
    ps_command = f'& {netsh_arg} advfirewall firewall delete rule {name_arg} | Out-Null'
    if not run_elevated_powershell_command(ps_command):
        logger.debug('Windows Firewall rule removal for web server was declined or failed')
        return False

    removed = not has_managed_webserver_firewall_rule()
    if removed:
        logger.info('Removed managed Windows Firewall rule for web server')
    return removed


def format_webserver_firewall_warning(status: FirewallStatus, port: int) -> str:
    """Return a plain-language localized warning explaining why Windows Firewall blocks phones on *port*."""
    if status == 'explicitly_blocked':
        return tr('Windows Firewall has a Block rule for this app that prevents phones from connecting. Remove it in Windows Defender Firewall.')
    if status == 'block_all_inbound':
        return tr(
            'Windows Firewall is set to block all incoming connections on this network. '
            'Turn off "Block all incoming connections" in Windows Defender Firewall so phones can connect.',
        )
    return tr('Windows Firewall is blocking phones from connecting on port {port}.', port=port)


def format_webserver_firewall_failure(port: int) -> str:
    """Return a plain-language localized warning when adding the Windows Firewall rule for *port* fails."""
    return tr(
        'Could not add the Windows Firewall rule for port {port}. '
        'Approve the administrator prompt or allow inbound TCP port {port} manually in Windows Defender Firewall.',
        port=port,
    )
