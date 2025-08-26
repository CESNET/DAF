#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: nat_detector.py
Description: NAT detector modul used to detect NAT devices.
"""

import logging

logger = logging.getLogger("NAT detector")


def annotate(ip_addresses: list, config: dict, ip_data_dict: dict) -> None:
    """
    Detects NAT devices based on the number of unique TTL values and source ports.
    This is temporary and will be replaced by a more robust solution in the future.

    Parameters
    ----------
    ip_addresses : list
        List of IP addresses to annotate.
    config : dict
        Dictionarz with DAF configuration settings.
    ip_data_dict : dict, optional
        Dictionary, where IP is key and value is pd.DataFrame with flows, by default None
    """

    # Check configuration
    if (
        "nat_detector" not in config
        or "field" not in config["nat_detector"]
        or "src_port_field" not in config["daf"]
    ):
        logger.error('Configuration or "field" parameter not found in configuration file')
        raise RuntimeError('NAT detector configuration or "field" parameter not found')

    _, first_value = next(iter(ip_data_dict.items()))
    if (
        config["nat_detector"]["field"] not in first_value.columns
        or config["daf"]["src_port_field"] not in first_value.columns
    ):
        logger.error(
            f"Field {config['nat_detector']['field']} or {config['daf']['src_port_field']} not found in DataFrame"
        )
        raise RuntimeError(
            f"NAT detector field {config['nat_detector']['field']} or {config['daf']['src_port_field']} not found in DataFrame"
        )

    # Initialize logging progress
    total_ips = len(ip_addresses)
    log_interval = max(1, total_ips // 10)

    # Iterate over IP addresses
    for cnt_ip, ip in enumerate(ip_addresses, start=1):
        if config["daf"]["progress_print"] and (cnt_ip % log_interval == 0 or cnt_ip == total_ips):
            progress = (cnt_ip / total_ips) * 100
            logger.info(f"    -- NAT detection ... {progress:.0f} %")

        ip_data = ip_data_dict.get(str(ip.ip_addr))
        if ip_data is None or ip_data.empty:
            continue

        ttl_values = ip_data[config["nat_detector"]["field"]]
        src_ports = ip_data[config["daf"]["src_port_field"]]
        ttl_values = ttl_values[ttl_values != 0]
        src_ports = src_ports[src_ports != 0]

        ttl_counts = ttl_values.value_counts()
        unique_ttl_values = ttl_counts.nunique()
        unique_src_ports = src_ports.nunique()

        # If less than 5 unique TTL values, continue
        if unique_ttl_values < 5:
            continue
        # If less than 500 unique source ports, continue
        elif unique_src_ports < 500:
            continue

        # More then 5 TTL values and more than 500 source ports
        ip.multi_device.append(
            ["NAT_detector", [ttl_counts.to_dict(), src_ports.value_counts().to_dict()]]
        )

    logger.info("    -- NAT detection ... DONE")
