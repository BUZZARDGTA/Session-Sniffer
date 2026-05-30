"""HTTP session for use throughout the project."""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from session_sniffer.constants.standalone import LOOKY_BASE_HOST

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0',
}

_RETRY_STRATEGY = Retry(
    total=3,
    connect=0,
    read=0,
    backoff_factor=0.5,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=['GET', 'POST'],
)
_ADAPTER = HTTPAdapter(max_retries=_RETRY_STRATEGY)
# Looky makes up to 8 concurrent background requests plus additional manual GUI lookups;
# a dedicated adapter with a larger pool prevents urllib3 connection pool overflow warnings.
_LOOKY_ADAPTER = HTTPAdapter(max_retries=_RETRY_STRATEGY, pool_maxsize=16)

# Global session object
session = requests.Session()
session.headers.update(HEADERS)
session.mount(LOOKY_BASE_HOST, _LOOKY_ADAPTER)
session.mount('https://', _ADAPTER)
session.mount('http://', _ADAPTER)
