"""Tests of the NAT detector."""

import pandas as pd

from dataset import FlowDataset
from helpers import DETECTORS, daf_config, flows_of, ips, module

nat = module(DETECTORS / "nat_detector" / "nat_detector.py")


def test_nat_detector():
    config = daf_config(nat_detector={"field": "TTL", "min_unique_ttl": 2, "min_unique_src_ports": 3})
    single, natted = ips("10.0.0.1", "10.0.0.2")
    flows = {
        "10.0.0.1": flows_of("10.0.0.1", rows=3, TTL=64, SRC_PORT=[1, 2, 3]),
        # TTL counts 1 and 2 give two distinct counts
        "10.0.0.2": flows_of("10.0.0.2", rows=3, TTL=[64, 128, 128], SRC_PORT=[1, 2, 3]),
    }

    nat.NATDetector(config).run([single, natted], flows)

    assert single.data["nat_detector"]["detected"] is False
    assert natted.data["nat_detector"]["detected"] is True
    assert natted.multi_device[0][0] == "NAT_detector"


def test_batch_matches_per_ip():
    config = daf_config(nat_detector={"field": "TTL", "min_unique_ttl": 2, "min_unique_src_ports": 2})
    detector = nat.NATDetector(config)
    flows = FlowDataset(
        pd.DataFrame(
            {
                "SRC_IP": ["10.0.0.1"] * 3 + ["10.0.0.2"] * 4,
                "TTL": [64, 64, 0, 64, 128, 128, 255],
                "SRC_PORT": [1, 2, 3, 1, 2, 3, 0],
            }
        ),
        "SRC_IP",
    )
    addresses = ips("10.0.0.1", "10.0.0.2")

    batch = detector.detect_all(addresses, flows)

    for ip in addresses:
        assert batch[str(ip.ip_addr)] == detector.detect(ip, flows[str(ip.ip_addr)])
