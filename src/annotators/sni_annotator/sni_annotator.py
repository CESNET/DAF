#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: sni_annotator.py
Description: SNI annotator module used to annotate IP addresses with SNI-based metadata.
"""

import csv
import logging
from collections import Counter
from pathlib import Path

import pandas as pd

from ip import Annotation

logger = logging.getLogger("SNI Annotator")


class SNI_database:
    """SNI Annotator class.

    Attributes
    ----------
    os_db : dict[dict[str, str]]
        Dictionary with SNI as key and OS family and group as values.
    """

    def __init__(self, db_path: str) -> None:
        """SNI Annotator constructor.

        Parameters
        ----------
        db_path : str
            Path to database file.

        Raises
        ------
        FileNotFoundError
            If the database file does not exist.
        ValueError
            If the database could not be loaded.
        """
        self.os_db = None

        db_path = Path(db_path)
        if not db_path.exists():
            logger.error(f"Database file {db_path} does not exist")
            raise FileNotFoundError("SNI_annotator:: Path to db_file does not exist")

        with db_path.open("r", encoding="utf-8") as file:
            csv_reader = csv.reader(file)
            self.os_db = {}

            header = next(csv_reader, None)
            if header != ["url", "uri", "os_family"]:
                logger.error(
                    f"Invalid database header: {header}, expected ['url', 'uri', 'os_family']"
                )
                raise ValueError("SNI_annotator:: Invalid database header")

            for i, row in enumerate(csv_reader):
                if len(row) < 3:
                    logger.warning(f"Skipping malformed row {i}: {row}")
                    continue
                self.os_db[row[0]] = {"path": row[1], "os": row[2]}

        if not self.os_db:
            logger.error("Unable to load database or database is empty")
            raise ValueError("SNI_annotator:: Unable to load database")

    def get_os(self, data: list) -> list:
        """Get OS family and group for given SNI.
        TODO: Upgrade strip, add class group...

        Parameters
        ----------
        data : list
            List with host and uri to classify.

        Returns
        -------
        list
            List with OS family and group.
        """

        os_family = os_type = group = _class = None
        host, uri = data

        host = host.strip()
        os = self.os_db.get(host, None)

        # Check if None or specific path necessary for classification
        if os is None or (os["path"] != "*" and (uri is None or os["path"] not in uri)):
            return [None, None, None, None]

        os = os["os"]

        if os == "windows":
            os_family = "windows"
            os_type = "windows"
        if os == "macos":
            os_family = "macos"
            os_type = "macos"
            group = "end-device"
        if os == "android":
            os_family = "android"
            os_type = "android"
            group = "end-device"
            _class = "mobile"
        if os in ["ubuntu", "mint"]:
            os_family = "linux"
            os_type = "ubuntu"
        if os == "debian":
            os_family = "linux"
            os_type = "debian"
        if os == "fedora":
            os_family = "linux"
            os_type = "fedora"
        if os == "opensuse":
            os_family = "linux"
            os_type = "opensuse"
        if os in ["archlinux", "manjaro"]:
            os_family = "linux"
            os_type = "arch linux"

        return [os_family, os_type, group, _class]


def get_most_common(lst: list) -> str:
    """Function used to get most common element from list.

    Parameters
    ----------
    lst : list
        List of elements to get most common from.

    Returns
    -------
    str
        Most common element from list.
    """

    if len(lst) == 0:
        return None
    counter = Counter(lst).most_common()

    return counter[0][0]


def get_SNIs_for_ip(ip: str, flows: pd.DataFrame, host_field: str, uri_field) -> list:
    """Function used to get [host,uri] pairs for given IP address.

    Parameters
    ----------
    ip : ipaddress.IPv4Address
        IP address to get TLS SNI for.
    flows : pd.DataFrame, optional
        DataFrame with flow records, by default None
    host_field : str
        Field in DataFrame with hostnames.
    uri_field : str
        Field in DataFrame with URIs.

    Returns
    -------
    list
        List of [host,uri] pairs for given IP address.
    """

    if len(flows) == 0:
        logger.warning("Empty DataFrame")
        return None

    ip_data = flows.get(ip, None)
    if uri_field is not None:
        snis = (
            ip_data[ip_data[host_field].notna()][[host_field, uri_field]]
            .replace({uri_field: {"": None}})
            .drop_duplicates()
            .values.tolist()
        )
    else:
        snis = ip_data[host_field].dropna().drop_duplicates().tolist()
        snis = [[value, None] for value in ip_data[host_field].dropna().drop_duplicates()]

    if len(snis) > 0:
        return snis

    return None


def get_annotation_from_sni(
    data: list, sin_database: SNI_database, min_annotation_count: int
) -> list:
    """Function used to get annotation based on TLS SNI.                            ----------------- TODO

    Parameters
    ----------
    host_names : list
        List of HTTP hostnames to get annotation for.
    annotator : sni_annotator.SNI
        Annotator used to get annotation.
    min_annotation_count : int
        Minimal number of annotated samples, needed to assign label.

    Returns
    -------
    list
        List of annotations for given HTTP hostnames.
    """

    os_family = []
    os_type = []
    groups = []
    classes = []
    multi_flag = []

    for hosturi in data:
        t_family, t_type, t_group, t_class = sin_database.get_os(hosturi)
        if t_family is not None:
            os_family.append(t_family)
        if t_type is not None:
            os_type.append(t_type)
        if t_group is not None:
            groups.append(t_group)
        if t_class is not None:
            classes.append(t_class)

    if len(set(os_family)) > 1:
        multi_flag.append(list(set(os_family)))

    if len(os_family) > 0 and Counter(os_family).most_common()[0][1] < min_annotation_count:
        return [None, None, None, None, None, multi_flag]

    return [
        get_most_common(groups),
        get_most_common(classes),
        get_most_common(os_family),
        get_most_common(os_type),
        None,
        multi_flag,
    ]


def get_fields_from_config(local_config: dict, first_value: pd.DataFrame) -> list:
    """Function used to get fields from configuration file.

    Parameters
    ----------
    local_config : dict
        Configuration of annotator.
    first_value : pd.DataFrame
        DataFrame for first ip, used to check fields.

    Returns
    -------
    list
        _description_
    """

    fields = []
    for field in local_config["fields"]:
        if isinstance(field, list) and len(field) == 2:
            host, uri = field
        else:
            host = field
            uri = None

        if host not in first_value.columns:
            logger.error(f"Field {host} not found in dataframe, skipping")
            continue
        if uri is not None and uri not in first_value.columns:
            logger.error(f"Field {uri} not found in dataframe, setting to None")
            uri = None

        fields.append([host, uri])

    return fields


def annotate(ip_addresses: list, config: dict, ip_data_dict=None) -> None:
    """
    Annotate a list of IP addresses with SNI-based information using a configured database.

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
        If the configuration or database file path is missing in the configuration.
    """

    if "sni_annotator" not in config or "db_file" not in config["sni_annotator"]:
        logger.error("Configuration or path to database not found in configuration file")
        raise RuntimeError("SNI Annotator:: Configuration or path to database not found")
    local_config = config["sni_annotator"]

    sni_db = SNI_database(local_config["db_file"])

    if len(local_config["fields"]) == 0:
        logger.error("No fields in configuration file, nothing to annotate")
        return

    _, first_value = next(iter(ip_data_dict.items()))
    fields = get_fields_from_config(local_config, first_value)

    total_ips = len(ip_addresses)
    log_interval = max(1, total_ips // 10)

    for cnt_ip, ip in enumerate(ip_addresses, start=1):
        if config["daf"]["progress_print"] and (cnt_ip % log_interval == 0 or cnt_ip == total_ips):
            progress = (cnt_ip / total_ips) * 100
            logger.info(f"    -- SNI Annotation ... {progress:.0f} %")

        for host, uri in fields:
            data = get_SNIs_for_ip(str(ip.ip_addr), ip_data_dict, host, uri)
            if data is not None:
                ip.add_data(f"sni_annotator_{host.split(' ')[-1]}", data)
                (
                    group,
                    _class,
                    os_family,
                    os_type,
                    os_version,
                    multi_flag,
                ) = get_annotation_from_sni(
                    data,
                    sni_db,
                    config["daf"]["min_annotation_count"],
                )

                if len(multi_flag) > 0:
                    ip.multi_device.append([host.split(" ")[-1], multi_flag])

                ip.add_annotation(
                    f"sni_annotator_{host.split(' ')[-1]}",
                    Annotation(group, _class, os_family, os_type, os_version),
                )
