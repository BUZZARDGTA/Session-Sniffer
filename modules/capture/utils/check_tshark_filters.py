"""Module for checking support for broadcast and multicast capture filters on a specified network interface using tshark."""
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def check_broadcast_multicast_support(tshark_path: Path, interface: str) -> tuple[bool, bool]:
    """Check if the given network interface supports 'broadcast' and 'multicast' capture filters using tshark.

    Args:
        tshark_path: Path to the tshark executable.
        interface: The name of the network interface to check.

    Returns:
        A tuple where the first value indicates support for 'broadcast', and the second indicates support for 'multicast' capture filters.
    """

    def run_capture_filter_test(capture_filter: str) -> bool:
        """Run tshark with a given capture filter and return whether it was successful.

        Args:
            capture_filter: The capture filter to test (e.g. "broadcast" or "multicast").

        Returns:
            True if tshark ran successfully with the given filter, False otherwise.
        """
        cmd = (
            str(tshark_path),
            '-i', interface,
            '-f', capture_filter,
            '-a', 'duration:0',
            '-Q',
        )
        try:
            subprocess.run(cmd, capture_output=True, check=True, encoding='utf-8', text=True)
        except subprocess.CalledProcessError:
            return False
        return True

    return (run_capture_filter_test('broadcast'), run_capture_filter_test('multicast'))
