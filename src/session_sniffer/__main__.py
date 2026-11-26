"""Package entrypoint for `python -m session_sniffer`."""

from session_sniffer.launcher.bootstrap import bootstrap

if __name__ == '__main__':
    bootstrap()
