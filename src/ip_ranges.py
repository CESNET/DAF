#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: ip_ranges.py
Description: Functions for loading IP ranges from CSV and selecting protected IPs from flows.
"""

import csv
import ipaddress
import logging
from pathlib import Path

import pandas as pd

from ip import IP

logger = logging.getLogger("load_ip_ranges")


def load_ip_ranges(filename: str) -> tuple:
    """
    Load IP addresses and networks from a CSV file.

    Parameters
    ----------
    filename : str
        The name or path of the file that contains the IP ranges.

    Returns
    -------
    tuple
        A tuple containing two lists: `protected_networks` and `protected_ip_addrs`.
    """

    if filename == "ALL":
        return None, None
    protected_networks = []
    protected_ip_addrs = []
    path = Path(filename)

    if not path.exists():
        logger.error(f"Config parameter ip_ranges: File {filename} does not exist")
        raise FileNotFoundError(f"Config parameter ip_ranges: File {filename} does not exist")

    with path.open("r") as f:
        reader = csv.reader(f, delimiter=",")
        for row in reader:
            if row[0] == "ip":
                continue
            if row[1] == "addr":
                protected_ip_addrs.append(row[0])
            elif row[1] == "network":
                protected_networks.append(ipaddress.ip_network(row[0]))
            else:
                print(
                    f"  -- warning: loading unknown type: {row[1]}, IP address or network: {row[0]} is ignored"
                )

    return protected_networks, protected_ip_addrs


def select_protected_ips(config: dict, flows: pd.DataFrame) -> list:
    """
    The function `select_protected_ips` takes a file containing IP ranges and a list of IP addresses,
    and returns a list of IP addresses that are either in the protected IP ranges or match a protected
    IP address.

    Parameters
    ----------
    config : dict
        A dictionary containing the configuration settings.
    flows : pd.DataFrame
        A DataFrame containing the IP flows.

    Returns
    -------
    list
        A list of IP addresses that are either in the list of protected IP addresses or within one
        of the protected network ranges.
    """

    if config["daf"]["src_ip_field"] not in flows.columns:
        logger.error(f"Column 'src_ip_field' not found in the dataframe")
        raise KeyError(f"Column 'src_ip_field' not found in the dataframe")
    if (
        config["daf"]["dst_ip_field"] is not None
        and config["daf"]["dst_ip_field"] not in flows.columns
    ):
        logger.error(f"Column 'dst_ip_field' not found in the dataframe")
        raise KeyError(f"Column 'dst_ip_field' not found in the dataframe")

    ips = flows[config["daf"]["src_ip_field"]].unique().tolist()
    if config["daf"]["dst_ip_field"] is not None:
        ips += flows[config["daf"]["dst_ip_field"]].unique().tolist()

    protected_networks, protected_ip_addrs = load_ip_ranges(config["daf"]["ip_ranges"])
    ip_addresses = []
    for ip in ips:
        if protected_networks is None and protected_ip_addrs is None:
            ip_addresses.append(IP(ip))
            continue
        if ip in protected_ip_addrs:
            ip_addresses.append(IP(ip))
        ip_addr = ipaddress.ip_address(ip)
        for net in protected_networks:
            if ip_addr in net:
                ip_addresses.append(IP(ip))
                break

    return ip_addresses
