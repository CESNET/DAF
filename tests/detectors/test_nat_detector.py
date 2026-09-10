"""Tests of the NAT detector."""

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
