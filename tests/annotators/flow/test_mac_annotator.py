"""Tests of the MAC annotator."""

from helpers import ANNOTATORS, ROOT, daf_config, flows_of, ips, module

mac = module(ANNOTATORS / "flow" / "mac_annotator" / "mac_annotator.py")
DB = ROOT / "dbs" / "mac_annotator-vendor_os_db.csv"


def test_mac_annotator():
    annotator = mac.MACAnnotator(daf_config(mac_annotator={"db_file": str(DB), "src_mac_field": "SRC_MAC"}))
    apple, shared = ips("10.0.0.1", "10.0.0.2")
    flows = {
        "10.0.0.1": flows_of("10.0.0.1", SRC_MAC="00:05:02:11:22:33"),
        "10.0.0.2": flows_of("10.0.0.2", rows=2, SRC_MAC=["00:05:02:00:00:01", "00:10:FA:00:00:02"]),
    }

    annotator.run([apple, shared], flows)

    assert apple.annotations["mac_annotator"].os_family == "macos"
    # two different MAC addresses behind one IP
    assert shared.multi_device[0][0] == "MAC"
