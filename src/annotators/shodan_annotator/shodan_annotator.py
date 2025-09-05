#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: shodan_annotator.py
Description: Shodan annotator module used to annotate IP addresses with Shodan-based metadata.
"""

import ipaddress
import logging
import time
from pathlib import Path

import requests

from ip import Annotation

logger = logging.getLogger("Shodan Annotator")
logging.getLogger("urllib3").setLevel(logging.WARNING)


def annotate(ip_addresses: list, config=None, ip_data_dict=None) -> None:
    """
    Annotate a list of IP addresses with Shodan-based information using the configured Shodan API and database.

    Parameters
    ----------
    ip_addresses : list
        List of IP addresses to annotate.
    config : dict
        Dictionarz with DAF configuration settings.
    ip_data_dict : dict, optional
        Dictionary, where IP is key and value is pd.DataFrame with flows, by default None

    Raises
    ------
    RuntimeError
        If the configuration or required Shodan settings are missing.
    """

    if "shodan_annotator" not in config or any(
        key not in config["shodan_annotator"]
        for key in ["shodan_api_key_file", "shodan_idb_url", "shodan_api_url"]
    ):
        logger.error("Configuration or path to database not found in configuration file")
        raise RuntimeError("Shodan Annotator configuration or path to database not found")

    total_ips = len(ip_addresses)
    log_interval = max(1, total_ips // 10)

    for cnt_ip, ip in enumerate(ip_addresses, start=1):
        if config["daf"]["progress_print"] and (cnt_ip % log_interval == 0 or cnt_ip == total_ips):
            progress = (cnt_ip / total_ips) * 100
            logger.info(f"    -- Shodan annotation ... {progress:.0f} %")

        shodan_os, shodan_open_ports, annotations = get_shodan_annotation_for_ip(
            ip.ip_addr, config["shodan_annotator"]
        )
        ip.add_data("shodan_annotation", [shodan_os, shodan_open_ports])
        if annotations is not None:
            ip.add_annotation("shodan_annotation", Annotation(*annotations))

    logger.info("    -- shodan annotation ... DONE")


def check_shodan_ip_data(ip: ipaddress.IPv4Address, config: dict) -> bool:
    """Function checks if shodan has information about IP.
    Uses public API: Shodan Internet DB

    Parameters
    ----------
    ip : ipaddress.IPv4Address
        IP to check availability
    conf : dict
        Module configuration settings

    Returns
    -------
    bool
        True is data available, False otherwise.
    """

    timeouts = 0
    while True:
        try:
            resp = requests.get(
                f"{config['shodan_idb_url']}{ip}",
                timeout=config["http_request_timeout"],
            )
            break
        except requests.ConnectionError as e:
            logger.error(f"ERROR: Shodan IDB API connection error: {e}")
            return False
        except requests.Timeout:
            # Timeout, maybe a rate-limitter blocked us, wait for a while and try again
            timeouts += 1
            if timeouts > config["max_timeouts"]:
                return False
            wait_time = config["base_wait_time"] * 2 ** (
                timeouts - 1
            )  # increase wait time, 10 sec, 20 sec, 40 sec, 80 sec,...
            time.sleep(wait_time)
            continue

    if resp.status_code == 200:
        return True

    return False


def get_shodan_annotation_for_ip(ip: ipaddress.IPv4Address, config: dict) -> tuple:
    """
    Retrieve Shodan annotation data for a given IP address.

    Parameters
    ----------
    ip : ipaddress.IPv4Address
        IP address to retrieve Shodan annotation for.
    config : dict
        Dictionary containing Shodan API configuration.

    Returns
    -------
    tuple
        Tuple containing:
        - str or None: Operating system information from Shodan.
        - list or None: List of open ports from Shodan.
        - tuple or None: (group, class, os_family, os_type, os_version) annotation, or None if unavailable.
    """
    # Check if shodan has data for IP
    if check_shodan_ip_data(ip, config) is False:
        return None, None, None

    # Load Shodan API key
    key_file = Path(config["shodan_api_key_file"])
    if not key_file.exists():
        logger.error(f"Shodan API key file {key_file} does not exist")
        raise FileNotFoundError(
            f"Shodan Annotator, path to API key file does not exist: {key_file}"
        )

    with key_file.open("r") as file:
        api_key = file.read().strip()

    # Gather data from API
    timeouts = 0
    while True:  # to support repeat after timeout
        try:
            resp = requests.get(
                f"{config['shodan_api_url']}{ip}?key={api_key}",
                timeout=config["http_request_timeout"],
            )
            break
        except requests.ConnectionError as e:
            print(f"ERROR: Shodan API connection error: {e}")
            return None, None, None
        except requests.Timeout:
            # Timeout, maybe a rate-limitter blocked us, wait for a while and try again
            timeouts += 1
            if timeouts > config["max_timeouts"]:
                return None, None, None
            wait_time = config["base_wait_time"] * 2 ** (
                timeouts - 1
            )  # increase wait time, 10 sec, 20 sec, 40 sec, 80 sec,...
            time.sleep(wait_time)
            continue

    if resp.status_code == 401:
        logger.error("Shodan unauthorized. Check your API key.")
        raise RuntimeError("Shodan Annotator:: Shodan unauthorized. Check your API key.")

    # Process it
    if resp.status_code == 200:
        resp_json = resp.json()
        (
            group,
            _class,
            os_family,
            os_type,
            os_version,
        ) = process_shodan_json_to_annotation(resp_json["os"], resp_json["ports"])

        return (
            resp_json["os"],
            resp_json["ports"],
            (group, _class, os_family, os_type, os_version),
        )

    return None, None, None


def process_shodan_json_to_annotation(os, ports):
    """
    Processes operating system and port information from Shodan data to generate annotation metadata.

    Parameters
    ----------
    os : str or None
        The operating system string as detected by Shodan, or None if not available.
    ports : list of int
        List of open port numbers detected on the host.

    Returns
    -------
    group : str or None
        The general group classification of the device (e.g., 'server', 'end-device', 'net-device'), or None if undetermined.
    _class : str or None
        The specific class of the device (e.g., 'web server', 'mobile', 'core router'), or None if undetermined.
    os_family : str or None
        The family of the operating system (e.g., 'windows', 'linux', 'macos', 'unix', 'other-unix-like'), or None if undetermined.
    os_type : str or None
        The type or name of the operating system, possibly normalized or adjusted, or None if undetermined.
    os_version : str or None
        The version string of the operating system, if detected, or None otherwise.
    """

    group = _class = os_family = os_type = os_version = None
    if os is not None:

        def num_there(s):
            return any(i.isdigit() for i in s)

        tmp = os.lower()
        if num_there(tmp) is True:
            os_version = tmp
            _ = ""
            for i in tmp.split():
                if num_there(i) is True:
                    break
                _ += i
                _ += " "
            os_type = _[:-1]
        else:
            os_type = tmp
        if os_type.startswith("windows"):
            os_family = "windows"
        elif os_type.startswith("mac"):
            os_family = "macos"
        elif os_type.startswith("unix") or "bsd" in os_type:
            os_family = "unix"
        else:
            os_family = "linux"

    if os_type == "synology diskstation manager (dsm)":
        group = "server"
        _class = "data server"
    elif os_type == "ios":
        if len(ports) > 0:
            # SSH will be opened always on router
            os_family = "other-unix-like"
            os_type = "cisco ios"
            group = "net-device"
            _class = "core router"
        else:
            os_family = "macos"
            os_type = "ios"
            group = "end-device"
            _class = "mobile"
    elif os_type == "android":
        group = "end-device"
        _class = "mobile"
    else:
        if len(ports) > 0:
            group = "server"
            # First handle other ports and at the end handle web ports
            if 53 in ports:
                _class = "dns server"
            elif 67 in ports:
                _class = "dhcp server"
            elif 123 in ports:
                _class = "ntp server"
            elif set([179, 264]) & set(ports):
                group = "net-device"
                _class = "core router"
            elif set([25, 110, 587, 993, 995]) & set(ports):
                _class = "mail server"
            elif 1701 in ports:
                _class = "vpn server"
            elif set([80, 443, 8080, 8443]) & set(ports):
                _class = "web server"
        else:
            if group is None and os_family is not None:
                group = "end-device"
                _class = "workstation"

    return group, _class, os_family, os_type, os_version
