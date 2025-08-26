#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: hostname_annotator.py
Description: Hostname annotator module used to annotate IP addresses with hostname-based metadata.
"""

import logging
import operator as op
import socket
import time
from pathlib import Path

import pandas as pd

from ip import Annotation

logger = logging.getLogger("Hostname Annotator")


def load_regex_rules(paths: list) -> dict:
    """
    Load regex rules from CSV files and return them as a dictionary.

    Parameters
    ----------
    paths : list
        List of pathlib.Path objects pointing to the CSV files. The order should be:
        [full-match.csv, sequences.csv, subsequences.csv].

    Returns
    -------
    dict
        Dictionary containing three keys:
            - "full-match": dict with hostname as key and annotation info as value.
            - "sequences": dict with sequence as key and annotation info as value.
            - "subsequences": dict with subsequence as key and annotation info as value,
              merged with the "sequences" dictionary.

    Raises
    ------
    FileNotFoundError
        If any of the provided paths does not exist.
    """
    rules = {
        "full-match": None,
        "sequences": None,
        "subsequences": None,
    }
    if not all([p.exists() for p in paths]):
        logger.error(f"Annotation file {paths} does not exist")
        raise FileNotFoundError(f"Hostname Annotator, path to database: {paths} does not exist")

    df = pd.read_csv(paths[0])
    rules["full-match"] = df.set_index("hostname").to_dict("index")

    df = pd.read_csv(paths[1])
    rules["sequences"] = df.set_index("sequence").to_dict("index")

    df = pd.read_csv(paths[2])
    rules["subsequences"] = df.set_index("subsequence").to_dict("index")
    rules["subsequences"].update(rules["sequences"])

    return rules


def get_regex_name(ip: str) -> str:
    """
    Perform a reverse DNS lookup to obtain the hostname for a given IP address.

    Parameters
    ----------
    ip : str
        IP address as a string.

    Returns
    -------
    str or None
        Hostname associated with the given IP address, or None if it cannot be determined.
    """
    try:
        return socket.getnameinfo((ip, 0), 0)[0]
    except socket.gaierror:
        return None


def annotate_by_sequence(
    ip,
    groups: list,
    classes: list,
    os_families: list,
    os_types: list,
    os_versions: list,
) -> bool:
    """
    Annotate the IP address based on sequences of groups, classes, OS families, OS types, and OS versions.

    Parameters
    ----------
    ip : TIP
        IP address object to annotate.
    groups : list
        List of group annotations.
    classes : list
        List of class annotations.
    os_families : list
        List of operating system families.
    os_types : list
        List of operating system types.
    os_versions : list
        List of operating system versions.

    Returns
    -------
    bool
        True if annotation was applied or sequence is not possible to tag, False otherwise.
    """
    if len(groups) == 1:
        ip.add_annotation(
            "hostname_annotator",
            Annotation(groups[0], classes[0], os_families[0], os_types[0], os_versions[0]),
        )
        return True
    elif len(set(groups)) == 1:
        if len(set(classes)) == 1:
            ip.add_annotation(
                "hostname_annotator",
                Annotation(groups[0], classes[0], os_families[0], os_types[0], os_versions[0]),
            )
            return True
        else:
            ip.add_annotation(
                "hostname_annotator",
                Annotation(groups[0], None, os_families[0], os_types[0], os_versions[0]),
            )
    elif len(groups) > 0:
        # the sequences is not possible to tag because of multiple different groups are find
        return True
    return False


def annotate(ip_addresses: list, config: dict, ip_data_dict=None) -> None:
    """
    Annotate IP addresses with hostname-based metadata using regex rules.

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
        If required database paths are missing.
    """

    required_dbs = ["full_db", "sequences_db", "subsequences_db"]
    if "hostname_annotator" not in config or not all(
        db in config["hostname_annotator"] for db in required_dbs
    ):
        logger.error("Configuration or path to database not found in configuration file")
        raise RuntimeError("Hostname Annotator:: Configuration or path to databases not found")

    rules = load_regex_rules([Path(config["hostname_annotator"][db]) for db in required_dbs])
    timeout = config["hostname_annotator"].get("timeout", 0.00001)

    total_ips = len(ip_addresses)
    log_interval = max(1, total_ips // 10)
    timestamp = time.time()
    for cnt_ip, ip in enumerate(ip_addresses, start=1):
        if config["daf"]["progress_print"] and (cnt_ip % log_interval == 0 or cnt_ip == total_ips):
            progress = (cnt_ip / total_ips) * 100
            logger.info(f"    -- reverse DNS queries annotation ... {progress:.0f} %")

        elapsed = time.time() - timestamp
        if elapsed < timeout:
            time.sleep(timeout - elapsed)
        timestamp = time.time()

        hostname = get_regex_name(str(ip.ip_addr))

        if hostname is None:
            continue
        ip.add_data("hostname_annotator", hostname)

        # full-math
        if hostname in rules["full-match"]:
            ip.add_annotation(
                "hostname_annotator",
                Annotation(
                    rules["full-match"][hostname]["group"],
                    rules["full-match"][hostname]["class"],
                    rules["full-match"][hostname]["os-family"],
                    rules["full-match"][hostname]["os-type"],
                    rules["full-match"][hostname]["os-version"],
                ),
            )
            continue
        # sequences
        splitted_revers_dns = hostname.split(".")
        groups = []
        classes = []
        os_families = []
        os_types = []
        os_versions = []
        for i in splitted_revers_dns:
            if i in rules["sequences"]:
                groups.append(rules["sequences"][i]["group"])
                classes.append(rules["sequences"][i]["class"])
                os_families.append(rules["sequences"][i]["os-family"])
                os_types.append(rules["sequences"][i]["os-type"])
                os_versions.append(rules["sequences"][i]["os-version"])
        if annotate_by_sequence(ip, groups, classes, os_families, os_types, os_versions):
            continue
        # subsequences
        groups = []
        classes = []
        os_families = []
        os_types = []
        os_versions = []
        for key in rules["subsequences"]:
            if op.contains(splitted_revers_dns[0], key):
                groups.append(rules["subsequences"][key]["group"])
                classes.append(rules["subsequences"][key]["class"])
                os_families.append(rules["subsequences"][key]["os-family"])
                os_types.append(rules["subsequences"][key]["os-type"])
                os_versions.append(rules["subsequences"][key]["os-version"])
        annotate_by_sequence(ip, groups, classes, os_families, os_types, os_versions)

    logger.info("    -- reverse DNS queries annotation ... DONE")
