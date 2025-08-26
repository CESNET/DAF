#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: mac_annotator.py
Description: Provides MAC address-based device annotation using OUI database.
"""

import csv
import ipaddress
import logging
from pathlib import Path

import pandas as pd

from ip import Annotation

logger = logging.getLogger("MAC Annotator")


class OUI_database:
    """MAC Annotator class.

    Attributes
    ----------
    os_db : dict[dict[str, str]]
        Dictionary with MAC as key and vendor and os family as values.
    """

    def __init__(self, config):
        """MAC Annotator constructor.

        Parameters
        ----------
        config_path : str, optional
            Path to configuration file, by default None

        Raises
        ------
        FileNotFoundError
            Raised when config file is not found.
        ValueError
            Raised when config file is not valid YAML.
        ValueError
            Raised when db_file is not found in the config file.
        FileNotFoundError
            Raised when path to db_file does not exist.
        ValueError
            Raised when database is not loaded.
        """

        self.os_db = None

        if "db_file" not in config["mac_annotator"]:
            logger.error("MAC_annotator:: db_file not found in the config file")
            raise ValueError("MAC_annotator:: db_file not found in the config file")

        db_path = Path(config["mac_annotator"]["db_file"])
        if not db_path.exists():
            logger.error(f"MAC_annotator:: database file {db_path} does not exist")
            raise FileNotFoundError(
                "MAC_annotator:: Path to db_file does not exist: {}".format(db_path)
            )

        with db_path.open("r", encoding="utf-8") as file:
            csv_reader = csv.reader(file)
            self.os_db = {row[0]: {"vendor": row[1], "os": row[2]} for row in csv_reader}

        if self.os_db is None:
            logger.error("Unable to load database")
            raise ValueError("MAC_annotator:: Unable to load database")

    def get_os(self, oui: str) -> str:
        """Function used to get OS family for given MAC.

        Parameters
        ----------
        oui : str
            OUI to get OS for.

        Returns
        -------
        str
            OS family for given OUI.
        """

        if oui in self.os_db:
            return self.os_db[oui]["os"]

        return None


def get_mac_for_ip(config, ip: ipaddress.IPv4Address, flows, field) -> list:
    """Function used to get MAC address for given IP.

    Parameters
    ----------
    ip : ipaddress.IPv4Address
        IP address to get MAC for.
    arg : argparse.Namespace
        Arguments from command line.
    flows : pd.DataFrame, optional
        DataFrame with flow records, by default None
    filename : str, optional
        File used to store partial results, by default None.

    Returns
    -------
    list
        List with MAC addresses for given IP.
    """

    if flows is None:
        return None

    ip_data = flows.get(ip, None)
    if ip_data is not None:
        macs = ip_data[field].dropna().drop_duplicates().tolist()
        if len(macs) > 0:
            return macs

    return None


def get_annotation_based_on_mac(mac: str, annotator: OUI_database) -> list:
    """Function used to get annotation based on MAC address.

    Parameters
    ----------
    mac : str
        MAC address to get annotation for.
    annotator : MacAnnotator
        Annotator used to get annotation.

    Returns
    -------
    list
        List with group, class and family.
    """

    group = _class = family = None

    if len(mac) > 8:
        mac = mac[:8]

    family = annotator.get_os(mac)

    if family == "android":
        group = "end-device"
        _class = "mobile"

    if family == "macos":
        group = "end-device"

    return [group, _class, family]


def annotate(ip_addresses: list, config: dict, ip_data_dict=None) -> None:
    """Function used to annotate IP addresses based on MAC addresses.

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
    ValueError
        Raised when module config file is not valid YAML.
    FileNotFoundError
        Raised when module config file is not found.
    ValueError
        Raised when db_file is not found in the config file.
    ValueError
        Raised when column src_ip or mac field is not found in the dataframe.
    """

    if "mac_annotator" not in config or "db_file" not in config["mac_annotator"]:
        logger.error("Configuration or path to database not found in configuration file")
        raise RuntimeError("MAC Annotator:: Configuration or path to databases not found")

    local_config = config["mac_annotator"]
    annotator = OUI_database(config)

    _, first_value = next(iter(ip_data_dict.items()))
    if (
        "src_mac_field" not in local_config
        or local_config["src_mac_field"] not in first_value.columns
    ):
        logger.error(f"Column {local_config['src_mac_field']} not found in the dataframe")
        raise ValueError(
            f"MAC Annotator:: Column {local_config['src_mac_field']} not found in the dataframe"
        )

    if config["daf"]["dst_ip_field"] is not None:
        dst_grouped_dfs = {
            k: v for k, v in pd.concat(ip_data_dict.values()).groupby(config["daf"]["dst_ip_field"])
        }

    total_ips = len(ip_addresses)
    log_interval = max(1, total_ips // 10)

    for cnt_ip, ip in enumerate(ip_addresses, start=1):
        if config["daf"]["progress_print"] and (cnt_ip % log_interval == 0 or cnt_ip == total_ips):
            progress = (cnt_ip / total_ips) * 100
            logger.info(f"    -- MAC annotation ... {progress:.0f} %")

        macs = get_mac_for_ip(
            config, ip.ip_addr, flows=ip_data_dict, field=local_config["src_mac_field"]
        )
        if config["daf"]["dst_ip_field"] is not None:
            if "dst_mac_field" not in local_config:
                logger.warning(
                    "MAC Annotator:: 'dst_ip_field' set but 'dst_mac_field' is missing in mac_annotator configuration. Skipping MAC annotation of dst IPs."
                )
            dst_macs = get_mac_for_ip(
                config,
                ip.ip_addr,
                flows=dst_grouped_dfs,
                field=local_config["dst_mac_field"],
            )
            if dst_macs is not None:
                macs += dst_macs

        if macs is not None:
            if len(macs) > 1:
                ip.multi_device.append(["MAC", macs])
                continue
            ip.add_data("mac_annotator", macs)

            group, _class, os_family = get_annotation_based_on_mac(macs[0], annotator)
            ip.add_annotation("mac_annotator", Annotation(group, _class, os_family, None, None))

    logger.info("    -- MAC annotation ...  DONE")
