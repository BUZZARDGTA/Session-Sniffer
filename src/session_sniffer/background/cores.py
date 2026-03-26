"""Background core loops for IP lookup, hostname resolution, and ping."""

from concurrent.futures import Future, ThreadPoolExecutor

import requests

from session_sniffer.background.tasks import gui_closed__event
from session_sniffer.core import ScriptControl, ThreadsExceptionHandler
from session_sniffer.models import IpApiResponse
from session_sniffer.networking.endpoint_ping_manager import PingResult, fetch_and_parse_ping
from session_sniffer.networking.exceptions import AllEndpointsExhaustedError
from session_sniffer.networking.http_session import session
from session_sniffer.networking.reverse_dns import lookup as reverse_dns_lookup
from session_sniffer.player.registry import PlayersRegistry


def iplookup_core() -> None:
    """Populate IP lookup data in the background using batch requests."""
    with ThreadsExceptionHandler():
        def throttle_until(requests_remaining: int, throttle_time: int) -> None:
            # Calculate sleep time only if there are remaining requests
            sleep_time = throttle_time / requests_remaining if requests_remaining > 0 else throttle_time

            # We sleep x seconds (just in case) to avoid triggering a "429" status code.
            gui_closed__event.wait(sleep_time)

        # Following values taken from https://ip-api.com/docs/api:batch the 03/04/2024.
        # max_requests = 15
        # max_throttle_time = 60
        max_batch_ip_api_ips = 100
        fields_to_lookup = (
            'continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,'
            'timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query'
        )

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            ips_to_lookup: list[str] = []

            for player in PlayersRegistry.get_default_sorted_players():
                if player.iplookup.ipapi.is_initialized:
                    continue

                ips_to_lookup.append(player.ip)

                if len(ips_to_lookup) == max_batch_ip_api_ips:
                    break

            if not ips_to_lookup:
                gui_closed__event.wait(1)
                continue

            try:
                response = session.post(
                    'http://ip-api.com/batch',
                    params={'fields': fields_to_lookup},
                    headers={'Content-Type': 'application/json'},
                    json=ips_to_lookup,
                    timeout=3,
                )
                response.raise_for_status()
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                gui_closed__event.wait(1)
                continue
            except requests.exceptions.HTTPError as e:
                # Handle rate limiting
                if isinstance(e.response, requests.Response) and e.response.status_code == requests.codes.too_many_requests:  # pylint: disable=no-member
                    throttle_until(int(e.response.headers['X-Rl']), int(e.response.headers['X-Ttl']))
                    continue
                raise  # Re-raise other HTTP errors

            iplookup_results_data = response.json()
            iplookup_results = [IpApiResponse.model_validate(item) for item in iplookup_results_data]

            for iplookup in iplookup_results:
                matched_player = PlayersRegistry.get_player_by_ip(iplookup.query)
                if matched_player is None:
                    continue

                matched_player.iplookup.ipapi.continent = iplookup.continent
                matched_player.iplookup.ipapi.continent_code = iplookup.continent_code
                matched_player.iplookup.ipapi.country = iplookup.country
                matched_player.iplookup.ipapi.country_code = iplookup.country_code
                matched_player.iplookup.ipapi.region = iplookup.region
                matched_player.iplookup.ipapi.region_code = iplookup.region_code
                matched_player.iplookup.ipapi.city = iplookup.city
                matched_player.iplookup.ipapi.district = iplookup.district
                matched_player.iplookup.ipapi.zip_code = iplookup.zip_code
                matched_player.iplookup.ipapi.lat = iplookup.lat
                matched_player.iplookup.ipapi.lon = iplookup.lon
                matched_player.iplookup.ipapi.time_zone = iplookup.time_zone
                matched_player.iplookup.ipapi.offset = iplookup.offset
                matched_player.iplookup.ipapi.currency = iplookup.currency
                matched_player.iplookup.ipapi.isp = iplookup.isp
                matched_player.iplookup.ipapi.org = iplookup.org
                matched_player.iplookup.ipapi.asn = iplookup.asn
                matched_player.iplookup.ipapi.as_name = iplookup.as_name

                matched_player.iplookup.ipapi.mobile = iplookup.mobile
                matched_player.iplookup.ipapi.proxy = iplookup.proxy
                matched_player.iplookup.ipapi.hosting = iplookup.hosting

                matched_player.iplookup.ipapi.is_initialized = True

            throttle_until(int(response.headers['X-Rl']), int(response.headers['X-Ttl']))


def hostname_core() -> None:
    """Resolve reverse DNS hostnames for players in the background."""
    with ThreadsExceptionHandler(), ThreadPoolExecutor(max_workers=32) as executor:
        futures: dict[Future[str], str] = {}  # Maps futures to their corresponding IPs
        pending_ips: set[str] = set()   # Tracks IPs currently being processed

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            for player in PlayersRegistry.get_default_sorted_players():
                if player.reverse_dns.is_initialized or player.ip in pending_ips:
                    continue

                future = executor.submit(reverse_dns_lookup, player.ip)
                futures[future] = player.ip
                pending_ips.add(player.ip)

            if not futures:
                gui_closed__event.wait(1)
                continue

            for future, ip in list(futures.items()):
                if not future.done():
                    continue

                futures.pop(future)
                pending_ips.remove(ip)

                hostname = future.result()

                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    continue

                matched_player.reverse_dns.hostname = hostname
                matched_player.reverse_dns.is_initialized = True

            gui_closed__event.wait(0.1)


def pinger_core() -> None:
    """Fetch and parse ping data for players in the background."""
    with ThreadsExceptionHandler(), ThreadPoolExecutor(max_workers=32) as executor:
        futures: dict[Future[PingResult], str] = {}  # Maps futures to their corresponding IPs
        pending_ips: set[str] = set()   # Tracks IPs currently being processed

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            for player in PlayersRegistry.get_default_sorted_players():
                if player.ping.is_initialized or player.ip in pending_ips:
                    continue

                future = executor.submit(fetch_and_parse_ping, player.ip)
                futures[future] = player.ip
                pending_ips.add(player.ip)

            if not futures:
                gui_closed__event.wait(1)
                continue

            for future, ip in list(futures.items()):
                if not future.done():
                    continue

                futures.pop(future)
                pending_ips.remove(ip)

                try:
                    ping_result = future.result()
                except AllEndpointsExhaustedError:
                    continue

                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    continue

                matched_player.ping.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
                matched_player.ping.ping_times = ping_result.ping_times
                matched_player.ping.packets_transmitted = ping_result.packets_transmitted
                matched_player.ping.packets_received = ping_result.packets_received
                matched_player.ping.packet_duplicates = ping_result.packet_duplicates
                matched_player.ping.packet_loss = ping_result.packet_loss
                matched_player.ping.packet_errors = ping_result.packet_errors
                matched_player.ping.rtt_min = ping_result.rtt_min
                matched_player.ping.rtt_avg = ping_result.rtt_avg
                matched_player.ping.rtt_max = ping_result.rtt_max
                matched_player.ping.rtt_mdev = ping_result.rtt_mdev
                matched_player.ping.is_initialized = True

            gui_closed__event.wait(0.1)
