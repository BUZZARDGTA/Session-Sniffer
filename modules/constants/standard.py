"""Module for defining constants that include only imports from standard Python libraries."""
import os
import re
from datetime import datetime
from pathlib import Path

from .external import LOCAL_TZ

# Get the SystemRoot environment variable dynamically
system_root = Path(os.environ.get('SYSTEMROOT', 'C:/Windows'))
system32 = system_root / 'System32'
CMD_EXE = system32 / 'cmd.exe'
SC_EXE = system32 / 'sc.exe'
SHUTDOWN_EXE = system32 / 'shutdown.exe'

SETTINGS_PATH = Path('Settings.ini')
USERIP_DATABASES_PATH = Path('UserIP Databases')
USERIP_LOGGING_PATH = Path('UserIP_Logging.log')
GEOLITE2_DATABASES_FOLDER_PATH = Path('GeoLite2 Databases')
SESSIONS_LOGGING_PATH = Path('Sessions Logging') / datetime.now(tz=LOCAL_TZ).strftime('%Y/%m/%d') / f"{datetime.now(tz=LOCAL_TZ).strftime('%Y-%m-%d_%H-%M-%S')}.log"

# Compiled regex for matching the optional time component in the version string
RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)')
RE_USERIP_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)')
RE_MODMENU_LOGS_USER_PATTERN = re.compile(r'^user:(?P<username>[\w._-]{1,16}), scid:\d{1,9}, ip:(?P<ip>[\d.]+), timestamp:\d{10}$')
RE_WIRESHARK_VERSION_PATTERN = re.compile(r'\b(?P<version>\d+\.\d+\.\d+)\b')
RE_BYTES_PATTERN = re.compile(r'(?P<NUM_OF_BYTES>[\d]+) bytes? from (?P<IP>\d+\.\d+\.\d+\.\d+): icmp_seq=(?P<ICMP_SEQ>\d+) ttl=(?P<TTL>\d+) time=(?P<TIME_MS>[\d\.]+) ms(?: \(DUP!\))?')
# NOTE: I don't need this one so far, but who knows maybe later.
# RE_HOST_UNREACHABLE_PATTERN = re.compile(r"From (?P<IP>\d+\.\d+\.\d+\.\d+) icmp_seq=(?P<ICMP_SEQ>\d+) Destination Host Unreachable")
RE_PACKET_STATS_PATTERN = re.compile(r'(?P<PACKETS_TRANSMITTED>\d+) packets? transmitted, (?P<PACKETS_RECEIVED>\d+) received(?:, \+(?P<DUPLICATES>\d+) duplicates?)?(?:, \+(?P<ERRORS>\d+) errors?)?, (?P<PACKET_LOSS_PERCENTAGE>\d+(?:\.\d+)?)% packet loss, time (?P<TIME>\d+)ms')
RE_RTT_STATS_PATTERN = re.compile(r'rtt min/avg/max/mdev = (?P<RTT_MIN>[\d\.]+)/(?P<RTT_AVG>[\d\.]+)/(?P<RTT_MAX>[\d\.]+)/(?P<RTT_MDEV>[\d\.]+) ms')
