"""HTTP session for use throughout the project."""
import requests

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0',
}

# Global session object
session = requests.Session()
session.headers.update(HEADERS)
