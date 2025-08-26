#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: hand_annotator.py
Description: Hand annotator module used to annotate IP addresses with hand-crafted annotations.
"""

import csv
import ipaddress
import logging
from pathlib import Path

from ip import Annotation

logger = logging.getLogger("Hand Annotator")


def load_annotation(path: Path) -> tuple:
    """
    The function `load_annotation` reads a CSV file containing hand annotation rules and stores the
    rules in two dictionaries, `device_hand_annotation` and `network_hand_annotation`, before returning
    them as a tuple.
    :return: The function `load_annotation` returns a tuple containing two dictionaries:
    `device_hand_annotation` and `network_hand_annotation`.
    """
    device_hand_annotation = {}
    network_hand_annotation = {}

    if not path.exists():
        logger.error(f"Annotation file {path} does not exist")
        raise FileNotFoundError(f"Hand Annotator, path to database: {path} does not exist")

    with path.open(mode="r") as f:
        reader = csv.reader(f, delimiter=",")
        for row in reader:
            if row[0] == "ip_address":
                continue
            if "/" in row[0]:
                network_hand_annotation[ipaddress.ip_network(row[0])] = (
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                )
            elif "{" in row[0]:
                prefix = row[0].split("{")[0]
                start_stop = row[0].split("{")[1].split("}")[0].split("-")
                for i in range(int(start_stop[0]), int(start_stop[1])):
                    device_hand_annotation[ipaddress.ip_address(f"{prefix}{i}")] = (
                        row[1],
                        row[2],
                        row[3],
                        row[4],
                        row[5],
                    )
            else:
                device_hand_annotation[ipaddress.ip_address(row[0])] = (
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                )

    return device_hand_annotation, network_hand_annotation


def annotate(ip_addresses: list, config=None, ip_data_dict=None) -> None:
    """
    Annotate a list of IP addresses with hand-crafted annotations.

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
        If the required configuration or database path is missing.
    """

    # Check configuration
    if "hand_annotator" not in config or "db" not in config["hand_annotator"]:
        logger.error("Configuration or path to database not found in configuration file")
        raise RuntimeError("Hand Annotator configuration or path to database not found")

    # Load annotations
    device_hand_annotation, network_hand_annotation = load_annotation(
        Path(config["hand_annotator"]["db"])
    )

    # Initialize logging progress
    total_ips = len(ip_addresses)
    log_interval = max(1, total_ips // 10)

    # Annotate IP addresses
    for cnt_ip, ip in enumerate(ip_addresses, start=1):
        if config["daf"]["progress_print"] and (cnt_ip % log_interval == 0 or cnt_ip == total_ips):
            progress = (cnt_ip / total_ips) * 100
            logger.info(f"    -- reverse DNS queries annotation ... {progress:.0f} %")

        if str(ip.ip_addr) in device_hand_annotation:
            ip.add_annotation("hand_annotator", Annotation(*device_hand_annotation[ip.ip_addr]))
        else:
            for network, annotation in network_hand_annotation.items():
                if ip.ip_addr in network:
                    ip.add_annotation("hand_annotator", Annotation(*annotation))
                    break

    logger.info("    -- hand annotation ... DONE")
