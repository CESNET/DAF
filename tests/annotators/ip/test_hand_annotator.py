"""Tests of the hand annotator."""

from helpers import ANNOTATORS, daf_config, ips, module

hand = module(ANNOTATORS / "ip" / "hand_annotator" / "hand_annotator.py")


def test_hand_annotator(tmp_path):
    rules = tmp_path / "hand.csv"
    rules.write_text(
        "ip_address,group,class,os-family,os-type,os-version\n"
        "10.0.0.1,end-device,workstation,windows,windows,\n"
        "10.0.1.{1-3},end-device,mobile,android,,\n"
        "192.168.0.0/30,end-device,printer,linux,,\n"
    )
    addresses = ips("10.0.0.1", "10.0.1.2", "192.168.0.2", "10.0.0.2")
    single, in_range, in_network, unknown = addresses

    hand.HandAnnotator(daf_config(hand_annotator={"db": str(rules)})).run(addresses)

    assert single.annotations["hand_annotator"]._class == "workstation"
    assert in_range.annotations["hand_annotator"]._class == "mobile"
    assert in_network.annotations["hand_annotator"]._class == "printer"
    assert "hand_annotator" not in unknown.annotations
