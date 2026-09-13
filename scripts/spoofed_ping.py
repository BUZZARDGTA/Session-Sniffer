"""Ping an IP address using the Check-Host API.

It continuously sends ping requests and displays results using ANSI terminal formatting.
"""  # noqa: INP001

import argparse
import ctypes
import enum
import re
import statistics
import sys
import time
from contextlib import suppress
from ipaddress import AddressValueError, IPv4Address
from typing import TYPE_CHECKING, Literal, NoReturn, TypeGuard, cast

import requests
from pydantic import BaseModel, ValidationError, field_validator

if TYPE_CHECKING:
    from collections.abc import Callable

NodeInfo = list[str]
PingTuple = list[str | float | int]
PingHop = list[PingTuple]
PingSuccess = list[PingHop]
PingError = list[dict[Literal['message'], str] | None]
PingNodeResult = PingSuccess | PingError | None
PingCheckResults = dict[str, PingNodeResult]


class CheckPingResponse(BaseModel):
    """Validated response model for the /check-ping endpoint."""

    request_id: str | None = None
    nodes: dict[str, list[str]] | None = None

    @field_validator('nodes')
    @classmethod
    def validate_nodes(cls, nodes: dict[str, list[str]] | None) -> dict[str, list[str]] | None:
        """Ensure each node contains at least country and city indexes."""
        if nodes is None:
            return None

        for node_name, node_data in nodes.items():
            if len(node_data) < NODE_INFO_MIN_LENGTH:
                message = f'Node "{node_name}" must include at least 3 values.'
                raise ValueError(message)

        return nodes


def validate_check_result_response(data: object) -> PingCheckResults:
    """Validate and return a check-result response."""
    if not isinstance(data, dict):
        message = f'Expected dict, got {type(data).__name__}'
        raise TypeError(message)

    for node_name, node_result in cast('dict[str, object]', data).items():
        if node_result is None:
            continue

        if is_ping_error(node_result) or is_ping_success(node_result):
            continue

        message = f'Unexpected ping result structure for node "{node_name}".'
        raise ValueError(message)

    return cast('PingCheckResults', data)


PING_ERROR_MIN_LENGTH = 2
PING_HOPS_PER_ATTEMPT = 4
PING_HOP_MIN_VALUES = 2
NODE_INFO_MIN_LENGTH = 3

MSGBOX_ICON_ERROR = 0x10


_ANSI_ESCAPE_PATTERN = re.compile(r'\033\[[0-9;]*m')


def _strip_ansi(text: str) -> str:
    """Return text with ANSI escape sequences removed."""
    return _ANSI_ESCAPE_PATTERN.sub('', text)


def _visible_length(text: str) -> int:
    """Return character length of text excluding ANSI escape sequences."""
    return len(_strip_ansi(text))


def _pad_cell(text: str, width: int, justify: str = 'left') -> str:
    """Pad text to specified visible width respecting ANSI escape sequences."""
    extra_spaces = max(0, width - _visible_length(text))
    if justify == 'right':
        return ' ' * extra_spaces + text
    if justify == 'center':
        left_spaces = extra_spaces // 2
        right_spaces = extra_spaces - left_spaces
        return ' ' * left_spaces + text + ' ' * right_spaces
    return text + ' ' * extra_spaces


_reconfigure_stdout = getattr(sys.stdout, 'reconfigure', None)
if callable(_reconfigure_stdout):
    _reconfigure_stdout(encoding='utf-8')


def print_line(message: str = '', end: str = '\n') -> None:
    """Write message to standard output without buffering delay."""
    sys.stdout.write(f'{message}{end}')
    sys.stdout.flush()


def show_error_msgbox(title: str, message: str) -> None:
    """Show a native Windows error message box and ignore UI failures."""
    with suppress(Exception):
        ctypes.windll.user32.MessageBoxW(0, message, title, MSGBOX_ICON_ERROR)


def exit_with_error(message: str) -> NoReturn:
    """Display an error, show a message box, and terminate the script gracefully."""
    print_line(f'{Colors.RED}{message}{Colors.RESET}')
    show_error_msgbox('Spoofed Ping Error', message)
    raise SystemExit(1)


def is_ping_error(value: object) -> TypeGuard[PingError]:
    """Return True when the node result is a known error shape."""
    if not isinstance(value, list):
        return False
    value_list = cast('list[object]', value)
    if len(value_list) < PING_ERROR_MIN_LENGTH:
        return False
    if value_list[0] is not None:
        return False
    error_data = value_list[1]
    if not isinstance(error_data, dict):
        return False
    error_data_dict = cast('dict[str, object]', error_data)
    message = error_data_dict.get('message')
    return isinstance(message, str)


def is_ping_success(value: object) -> TypeGuard[PingSuccess]:
    """Return True when the node result contains ping samples."""
    if not isinstance(value, list):
        return False

    value_list = cast('list[object]', value)
    for ping in value_list:
        if not isinstance(ping, list):
            return False
        ping_list = cast('list[object]', ping)
        if len(ping_list) < PING_HOPS_PER_ATTEMPT:
            return False

        for hop in ping_list[:PING_HOPS_PER_ATTEMPT]:
            if not isinstance(hop, list):
                return False
            hop_list = cast('list[object]', hop)
            if len(hop_list) < PING_HOP_MIN_VALUES:
                return False

    return True


CHECK_HOST_API = 'https://check-host.net'


class Colors(enum.StrEnum):
    """ANSI color codes for terminal formatting."""

    CYAN = '\033[38;2;58;150;221m'
    CYAN_LIGHT = '\033[38;2;97;214;214m'
    GREEN = '\033[38;2;19;161;14m'
    YELLOW = '\033[38;2;193;156;0m'
    YELLOW_LIGHT = '\033[38;2;249;241;165m'
    ORANGE = '\033[38;2;255;95;0m'
    RED = '\033[38;2;197;15;31m'
    RED_LIGHT = '\033[38;2;231;72;86m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


PING_COLOR_MAP = {
    4: Colors.GREEN,
    3: Colors.YELLOW,
    2: Colors.ORANGE,
    1: Colors.RED,
}


def format_ping_table(
    target_ip: str,
    rows: list[list[str]],
) -> str:
    """Format ping results into a single-border box-drawing text table with ANSI styling."""
    headers = [
        f'{Colors.CYAN_LIGHT}Country{Colors.RESET}',
        f'{Colors.CYAN_LIGHT}City{Colors.RESET}',
        f'{Colors.BOLD}{Colors.CYAN_LIGHT}Success{Colors.RESET}',
        f'{Colors.GREEN}Min RTT (ms){Colors.RESET}',
        f'{Colors.YELLOW}Avg RTT (ms){Colors.RESET}',
        f'{Colors.RED}Max RTT (ms){Colors.RESET}',
    ]
    alignments = ['left', 'left', 'center', 'right', 'right', 'right']

    column_widths = [_visible_length(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(column_widths):
                column_widths[i] = max(column_widths[i], _visible_length(cell))

    plain_title = f'Ping Results from {target_ip}'
    styled_title = f'{Colors.CYAN}Ping Results from {Colors.CYAN_LIGHT}{target_ip}{Colors.RESET}'

    total_inner_width = sum(width + 2 for width in column_widths) + (len(column_widths) - 1)
    min_inner_width = len(plain_title) + 2
    if min_inner_width > total_inner_width:
        extra_width = min_inner_width - total_inner_width
        current_content_width = sum(column_widths) or 1
        scale = (current_content_width + extra_width) / current_content_width
        column_widths = [int(width * scale) for width in column_widths]
        remaining = (current_content_width + extra_width) - sum(column_widths)
        if remaining > 0:
            column_widths[-1] += remaining
        total_inner_width = sum(width + 2 for width in column_widths) + (len(column_widths) - 1)

    lines: list[str] = [
        f'┌{"─" * total_inner_width}┐',
        f'│{_pad_cell(styled_title, total_inner_width, "center")}│',
        f'├{"┬".join("─" * (width + 2) for width in column_widths)}┤',
        f'│ {" │ ".join(_pad_cell(header, width, "left") for header, width in zip(headers, column_widths, strict=True))} │',
        f'├{"┼".join("─" * (width + 2) for width in column_widths)}┤',
    ]

    for row in rows:
        formatted_cells = [
            _pad_cell(cell, width, align)
            for cell, width, align in zip(row, column_widths, alignments, strict=True)
        ]
        lines.append(f'│ {" │ ".join(formatted_cells)} │')

    lines.append(f'└{"┴".join("─" * (width + 2) for width in column_widths)}┘')
    return '\n'.join(lines)


def ping_loop(target_ip: str, session: requests.Session) -> None:
    """Continuously pings the target IP until the user closes the script."""

    def send_ping_request(ip: str) -> tuple[str | None, dict[str, NodeInfo] | None]:
        """Send a ping request to the Check-Host API."""
        response = session.get(f'{CHECK_HOST_API}/check-ping?host={ip}', headers={'Accept': 'application/json'})
        response.raise_for_status()

        try:
            payload = CheckPingResponse.model_validate(response.json())
        except ValidationError as e:
            exit_with_error(f'Invalid response from check-ping endpoint: {e}')

        request_id = payload.request_id
        if request_id is None:
            return None, None

        nodes = payload.nodes
        if nodes is None:
            return None, None

        if not nodes:
            return None, None

        return request_id, nodes

    def get_ping_results(request_id: str, delay: int = 10) -> PingCheckResults:
        """Fetch the results using the request ID."""
        for i in range(delay, 0, -1):
            print_line(f'{Colors.CYAN}Waiting {Colors.CYAN_LIGHT}{i}{Colors.CYAN} second{pluralize(i)} for ping request to complete...  {Colors.RESET}', end='\r')
            time.sleep(1)
        print_line(' ' * 50, end='\r')

        response = session.get(f'{CHECK_HOST_API}/check-result/{request_id}', headers={'Accept': 'application/json'})
        response.raise_for_status()

        try:
            return validate_check_result_response(response.json())
        except (TypeError, ValueError) as e:
            exit_with_error(f'Invalid response from check-result endpoint: {e}')

    def pluralize(count: int, singular: str = '', plural: str = 's') -> str:
        """Return the singular/plural suffix based on a count.

        Args:
            count: The count to decide plurality.
            singular: Suffix to use when count is exactly 1.
            plural: Suffix to use otherwise.

        Returns:
            The chosen suffix.
        """
        return singular if count == 1 else plural

    def get_rtt_gradient_color(val: int) -> str:
        val = min(max(val, 0), 3000) * 0xFF // 3000
        return f'\033[38;2;{val};{(0xFF - val)};0m'

    def color_ping_result(successful_pings: int) -> str:
        """Return a color-coded string based on successful pings."""
        color = PING_COLOR_MAP.get(successful_pings, Colors.RED)
        return f'{color}{successful_pings}{Colors.RESET}'

    def parse_successful_pings(
        pings: PingSuccess,
        append_global_rtt: Callable[[float | int], None],
    ) -> tuple[int, list[float | int]]:
        """Extract successful ping count and RTT values from a success response."""
        successful_pings = 0
        this_rtt_values: list[float | int] = []

        for ping in pings:
            for hop in ping[:PING_HOPS_PER_ATTEMPT]:
                result = hop[0]
                if not isinstance(result, str):
                    message = f'Expected "str", got "{type(result).__name__}"'
                    raise TypeError(message)
                rtt = hop[1]
                if not isinstance(rtt, (float, int)):
                    message = f'Expected "(float, int)", got "{type(rtt).__name__}"'
                    raise TypeError(message)

                if result == 'OK':
                    successful_pings += 1

                this_rtt_values.append(rtt)
                append_global_rtt(rtt)

        return successful_pings, this_rtt_values

    def build_result_row(
        node: str,
        pings: PingNodeResult,
        all_nodes: dict[str, NodeInfo],
        append_global_rtt: Callable[[float | int], None],
    ) -> list[str]:
        """Build a table row for one node and append RTT values to global stats."""
        node_info = all_nodes.get(node)
        if node_info is None or len(node_info) < NODE_INFO_MIN_LENGTH:
            message = f'Expected node info list with at least 3 items for node "{node}"'
            raise TypeError(message)

        country = node_info[1]
        city = node_info[2]

        status_message: str | None = None
        successful_pings = 0
        this_rtt_values: list[float | int] = []

        if pings is None:
            status_message = 'Inactivity timeout'
        elif is_ping_error(pings):
            error_data = pings[1]
            status_message = error_data.get('message', 'Unknown error') if isinstance(error_data, dict) else 'Unknown error'
        elif is_ping_success(pings):
            successful_pings, this_rtt_values = parse_successful_pings(pings, append_global_rtt)
        else:
            status_message = 'Unexpected response format'

        rows = [
            country,
            city,
            f'{color_ping_result(successful_pings)}/{Colors.GREEN}4{Colors.RESET}',
        ]

        if this_rtt_values:
            rtt_min = min(this_rtt_values) * 1000
            rtt_avg = statistics.mean(this_rtt_values) * 1000
            rtt_max = max(this_rtt_values) * 1000
            rtt_min_color = get_rtt_gradient_color(round(rtt_min))
            rtt_avg_color = get_rtt_gradient_color(round(rtt_avg))
            rtt_max_color = get_rtt_gradient_color(round(rtt_max))
            rows.extend(
                [
                    f'{rtt_min_color}{round(rtt_min, 1)}{Colors.RESET} ms',
                    f'{rtt_avg_color}{round(rtt_avg, 1)}{Colors.RESET} ms',
                    f'{rtt_max_color}{round(rtt_max, 1)}{Colors.RESET} ms',
                ],
            )
        else:
            rows.extend(
                [
                    f'{Colors.RED}{status_message}{Colors.RESET}',
                    f'{Colors.RED}{status_message}{Colors.RESET}',
                    f'{Colors.RED}{status_message}{Colors.RESET}',
                ],
            )

        return rows

    while True:
        request_id, nodes = send_ping_request(target_ip)

        if not request_id or not nodes:
            print_line(f'{Colors.RED}Failed to send ping request to {Colors.RED_LIGHT}{target_ip}{Colors.RED}.{Colors.RESET}')

            for i in range(100, 0, -1):
                print_line(f'{Colors.YELLOW}Retrying in {Colors.YELLOW_LIGHT}{i}{Colors.YELLOW} second{pluralize(i)}...{Colors.RESET}   ', end='\r')
                time.sleep(1)

            print_line('\n')
            continue

        result_url = f'{CHECK_HOST_API}/check-result/{request_id}'
        print_line(
            f'{Colors.CYAN}Ping request sent to {Colors.CYAN_LIGHT}{target_ip}{Colors.CYAN}. '
            f'Result API link: {Colors.CYAN_LIGHT}{Colors.BOLD}{result_url}{Colors.RESET}',
        )

        results: PingCheckResults = get_ping_results(request_id)
        if not results:
            print_line(f'{Colors.RED}Failed to retrieve ping results.{Colors.RESET}')
            time.sleep(10)
            continue

        global_rtt_values: list[float | int] = []
        table_rows: list[list[str]] = []

        for node, pings in results.items():
            row = build_result_row(node, pings, nodes, global_rtt_values.append)
            table_rows.append(row)

        print_line()
        print_line(format_ping_table(target_ip, table_rows))

        if global_rtt_values:
            global_rtt_min = min(global_rtt_values) * 1000
            global_rtt_avg = statistics.mean(global_rtt_values) * 1000
            global_rtt_max = max(global_rtt_values) * 1000
            global_rtt_min_color = get_rtt_gradient_color(round(global_rtt_min))
            global_rtt_avg_color = get_rtt_gradient_color(round(global_rtt_avg))
            global_rtt_max_color = get_rtt_gradient_color(round(global_rtt_max))

            print_line(f'\n{Colors.CYAN}RTT Statistics {Colors.CYAN_LIGHT}(All Nodes Combined){Colors.CYAN}:{Colors.RESET}')
            print_line(f'{Colors.GREEN}Min RTT:{Colors.RESET} {global_rtt_min_color}{str(round(global_rtt_min, 1)).ljust(6)}{Colors.RESET} ms')
            print_line(f'{Colors.YELLOW}Avg RTT:{Colors.RESET} {global_rtt_avg_color}{str(round(global_rtt_avg, 1)).ljust(6)}{Colors.RESET} ms')
            print_line(f'{Colors.RED}Max RTT:{Colors.RESET} {global_rtt_max_color}{str(round(global_rtt_max, 1)).ljust(6)}{Colors.RESET} ms')
        else:
            print_line(f'\n{Colors.RED}No RTT data available.{Colors.RESET}')

        print_line()
        print_line(f'{Colors.BOLD}{Colors.YELLOW_LIGHT}- {Colors.RESET}' * 22)
        print_line()

        for i in range(20, 0, -1):
            print_line(f'{Colors.CYAN}Waiting {Colors.CYAN_LIGHT}{i}{Colors.CYAN} second{pluralize(i)} before the next ping request...{Colors.RESET}  ', end='\r')
            time.sleep(1)
        print_line(' ' * 50, end='\r')


def is_ipv4_address(ip_address: str, /) -> bool:
    """Check if the given IP address is a valid IPv4 address."""
    with suppress(AddressValueError):
        IPv4Address(ip_address)
        return True
    return False


def main() -> None:
    """Parse arguments and start the ping loop for the target IP."""
    parser = argparse.ArgumentParser(description='Ping an IP using Check-Host API.')
    parser.add_argument('ip', metavar='<ip>', type=str, help='Target IP to ping')
    args = parser.parse_args()

    target_ip = args.ip.strip() if isinstance(args.ip, str) else None
    if not target_ip:
        print_line(f'{Colors.RED}Error: No IP address provided.{Colors.RESET}')
        sys.exit(1)

    if not is_ipv4_address(target_ip):
        print_line(f"{Colors.RED}Error: '{Colors.RED_LIGHT}{target_ip}{Colors.RED}' is not a valid IP address.{Colors.RESET}")
        sys.exit(1)

    try:
        with requests.Session() as session:
            session.headers.update(
                {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:155.0) Gecko/20100101 Firefox/155.0',
                    'Accept': 'application/json',
                },
            )
            # session.verify = False
            ping_loop(target_ip, session)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
