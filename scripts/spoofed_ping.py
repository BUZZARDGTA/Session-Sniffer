"""Ping an IP address using the Check-Host API.

It continuously sends ping requests and displays results using Rich formatting.
"""  # noqa: INP001
import argparse
import ctypes
import enum
import statistics
import sys
import time
from contextlib import suppress
from ipaddress import AddressValueError, IPv4Address
from typing import TYPE_CHECKING, Literal, NoReturn, TypeGuard, cast, override

import requests
from pydantic import BaseModel, ValidationError, field_validator
from rich import print as rprint
from rich.table import Table

if TYPE_CHECKING:
    from collections.abc import Callable

NodeInfo = list[str]
PingTuple = list[str | float | int]
PingHop = list[PingTuple]
PingSuccess = list[PingHop]
PingError = list[None | dict[Literal['message'], str]]
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
                error_msg = f'Node "{node_name}" must include at least 3 values.'
                raise ValueError(error_msg)

        return nodes


def validate_check_result_response(data: object) -> PingCheckResults:
    """Validate and return a check-result response."""
    if not isinstance(data, dict):
        error_msg = f'Expected dict, got {type(data).__name__}'
        raise TypeError(error_msg)

    for node_name, node_result in cast('dict[str, object]', data).items():
        if node_result is None:
            continue

        if is_ping_error(node_result) or is_ping_success(node_result):
            continue

        error_msg = f'Unexpected ping result structure for node "{node_name}".'
        raise ValueError(error_msg)

    return cast('PingCheckResults', data)


PING_ERROR_MIN_LENGTH = 2
PING_HOPS_PER_ATTEMPT = 4
PING_HOP_MIN_VALUES = 2
NODE_INFO_MIN_LENGTH = 3

MSGBOX_ICON_ERROR = 0x10


def show_error_msgbox(title: str, message: str) -> None:
    """Show a native Windows error message box and ignore UI failures."""
    with suppress(Exception):
        ctypes.windll.user32.MessageBoxW(0, message, title, MSGBOX_ICON_ERROR)


def exit_with_error(message: str) -> NoReturn:
    """Display an error, show a message box, and terminate the script gracefully."""
    rprint(f'[{Colors.RED}]{message}[/{Colors.RED}]')
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
    """Hex color codes for Rich formatting."""

    CYAN = '3a96dd'
    CYAN_LIGHT = '61d6d6'
    GREEN = '13a10e'
    YELLOW = 'c19c00'
    YELLOW_LIGHT = 'f9f1a5'
    ORANGE = 'ff5f00'
    RED = 'c50f1f'
    RED_LIGHT = 'e74856'

    @override
    def __str__(self) -> str:
        """Automatically returns the color with a '#' prefix."""
        return f'#{self.value}'


PING_COLOR_MAP = {
    4: Colors.GREEN,
    3: Colors.YELLOW,
    2: Colors.ORANGE,
    1: Colors.RED,
}


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
            rprint(f'[{Colors.CYAN}]Waiting [{Colors.CYAN_LIGHT}]{i}[/{Colors.CYAN_LIGHT}] second{pluralize(i)} for ping request to complete...  ', end='\r')
            time.sleep(1)
        rprint(' ' * 50, end='\r')

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
        return f'#{val:02X}{(0xFF - val):02X}00'

    def color_ping_result(successful_pings: int) -> str:
        """Return a color-coded string based on successful pings."""
        color = PING_COLOR_MAP.get(successful_pings, Colors.RED)
        return f'[{color}]{successful_pings}[/{color}]'

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
                    error_msg = f'Expected "str", got "{type(result).__name__}"'
                    raise TypeError(error_msg)
                rtt = hop[1]
                if not isinstance(rtt, (float, int)):
                    error_msg = f'Expected "(float, int)", got "{type(rtt).__name__}"'
                    raise TypeError(error_msg)

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
            error_msg = f'Expected node info list with at least 3 items for node "{node}"'
            raise TypeError(error_msg)

        country = node_info[1]
        city = node_info[2]

        message: str | None = None
        successful_pings = 0
        this_rtt_values: list[float | int] = []

        if pings is None:
            message = 'Inactivity timeout'
        elif is_ping_error(pings):
            error_data = pings[1]
            message = error_data.get('message', 'Unknown error') if isinstance(error_data, dict) else 'Unknown error'
        elif is_ping_success(pings):
            successful_pings, this_rtt_values = parse_successful_pings(pings, append_global_rtt)
        else:
            message = 'Unexpected response format'

        rows = [
            country,
            city,
            f'{color_ping_result(successful_pings)}/[{Colors.GREEN}]4[/{Colors.GREEN}]',
        ]

        if this_rtt_values:
            rtt_min = min(this_rtt_values) * 1000
            rtt_avg = statistics.mean(this_rtt_values) * 1000
            rtt_max = max(this_rtt_values) * 1000
            rtt_min_color = get_rtt_gradient_color(round(rtt_min))
            rtt_avg_color = get_rtt_gradient_color(round(rtt_avg))
            rtt_max_color = get_rtt_gradient_color(round(rtt_max))
            rows.extend([
                f'[{rtt_min_color}]{round(rtt_min, 1)}[/{rtt_min_color}] ms',
                f'[{rtt_avg_color}]{round(rtt_avg, 1)}[/{rtt_avg_color}] ms',
                f'[{rtt_max_color}]{round(rtt_max, 1)}[/{rtt_max_color}] ms',
            ])
        else:
            rows.extend([
                f'[{Colors.RED}]{message}[/{Colors.RED}]',
                f'[{Colors.RED}]{message}[/{Colors.RED}]',
                f'[{Colors.RED}]{message}[/{Colors.RED}]',
            ])

        return rows

    while True:
        request_id, nodes = send_ping_request(target_ip)

        if not request_id or not nodes:
            rprint(f'[{Colors.RED}]Failed to send ping request to [{Colors.RED_LIGHT}]{target_ip}[/{Colors.RED_LIGHT}].[/{Colors.RED}]')

            for i in range(100, 0, -1):
                rprint(f'[{Colors.YELLOW}]Retrying in [{Colors.YELLOW_LIGHT}]{i}[/{Colors.YELLOW_LIGHT}] second{pluralize(i)}...[/{Colors.YELLOW}]   ', end='\r')
                time.sleep(1)

            rprint('\n')
            continue

        result_url = f'{CHECK_HOST_API}/check-result/{request_id}'
        rprint(
            f'[{Colors.CYAN}]Ping request sent to [{Colors.CYAN_LIGHT}]{target_ip}[/{Colors.CYAN_LIGHT}]. '
            f'Result API link: [link={result_url}][{Colors.CYAN_LIGHT} bold]{result_url}[/{Colors.CYAN_LIGHT} bold][/link][/{Colors.CYAN}]',
        )

        results: PingCheckResults = get_ping_results(request_id)
        if not results:
            rprint(f'[{Colors.RED}]Failed to retrieve ping results.[/{Colors.RED}]')
            time.sleep(10)
            continue

        global_rtt_values: list[float | int] = []

        table = Table(
            title=(
                f'[{Colors.CYAN}]Ping Results from[/{Colors.CYAN}] '
                f'[{Colors.CYAN_LIGHT}]{target_ip}[/{Colors.CYAN_LIGHT}]'
            ),
            show_header=True,
            header_style=f'bold {Colors.CYAN_LIGHT}',
        )
        table.add_column('Country',      header_style=f'{Colors.CYAN_LIGHT}')
        table.add_column('City',         header_style=f'{Colors.CYAN_LIGHT}')
        table.add_column('Success',      header_style=f'bold {Colors.CYAN_LIGHT}', justify='center')
        table.add_column('Min RTT (ms)', header_style=f'{Colors.GREEN}',  justify='right')
        table.add_column('Avg RTT (ms)', header_style=f'{Colors.YELLOW}', justify='right')
        table.add_column('Max RTT (ms)', header_style=f'{Colors.RED}',    justify='right')

        for node, pings in results.items():
            rows = build_result_row(node, pings, nodes, global_rtt_values.append)
            table.add_row(*rows)

        rprint()
        rprint(table)

        if global_rtt_values:
            global_rtt_min = min(global_rtt_values) * 1000
            global_rtt_avg = statistics.mean(global_rtt_values) * 1000
            global_rtt_max = max(global_rtt_values) * 1000
            global_rtt_min_color = get_rtt_gradient_color(round(global_rtt_min))
            global_rtt_avg_color = get_rtt_gradient_color(round(global_rtt_avg))
            global_rtt_max_color = get_rtt_gradient_color(round(global_rtt_max))

            rprint('\n[cyan]RTT Statistics [cyan]([/cyan]All Nodes Combined[cyan])[/cyan]:[/cyan]')
            rprint(f'[{Colors.GREEN}]Min RTT:[/{Colors.GREEN}] [{global_rtt_min_color}]{str(round(global_rtt_min, 1)).ljust(6)}[/{global_rtt_min_color}] ms')
            rprint(f'[{Colors.YELLOW}]Avg RTT:[/{Colors.YELLOW}] [{global_rtt_avg_color}]{str(round(global_rtt_avg, 1)).ljust(6)}[/{global_rtt_avg_color}] ms')
            rprint(f'[{Colors.RED}]Max RTT:[/{Colors.RED}] [{global_rtt_max_color}]{str(round(global_rtt_max, 1)).ljust(6)}[/{global_rtt_max_color}] ms')
        else:
            rprint(f'\n[{Colors.RED}]No RTT data available.[/{Colors.RED}]')

        rprint()
        rprint(f'[bold {Colors.YELLOW_LIGHT}]- [/bold {Colors.YELLOW_LIGHT}]' * 22)
        rprint()

        for i in range(20, 0, -1):
            rprint(f'[{Colors.CYAN}]Waiting [{Colors.CYAN_LIGHT}]{i}[/{Colors.CYAN_LIGHT}] second{pluralize(i)} before the next ping request...[/{Colors.CYAN}]  ', end='\r')
            time.sleep(1)
        rprint(' ' * 50, end='\r')


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
        rprint(f'[{Colors.RED}]Error: No IP address provided.[/{Colors.RED}]')
        sys.exit(1)

    if not is_ipv4_address(target_ip):
        rprint(f"[{Colors.RED}]Error: '[{Colors.RED_LIGHT}]{target_ip}[/{Colors.RED_LIGHT}]' is not a valid IP address.[/{Colors.RED}]")
        sys.exit(1)

    try:
        with requests.Session() as session:
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:135.0) Gecko/20100101 Firefox/135.0',
                'Accept': 'application/json',
            })
            # session.verify = False
            ping_loop(target_ip, session)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
