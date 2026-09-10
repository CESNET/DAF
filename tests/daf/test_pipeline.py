"""Tests of the annotation pipeline."""

import argparse
import json

import pandas as pd

from annotation import Annotation
from core import Detector, FlowAnnotator, IPAnnotator
from daf import DAFApplication
from helpers import daf_config

START = pd.Timestamp("2026-01-01T10:00:00Z")


class GroupAnnotator(IPAnnotator):
    name = "group_annotator"

    def setup(self):
        self.calls = {}

    def annotate_ip(self, ip):
        address = str(ip.ip_addr)
        self.calls[address] = self.calls.get(address, 0) + 1
        ip.add_annotation(self.name, Annotation("end-device", None, None, None, None))


class OSAnnotator(FlowAnnotator):
    name = "os_annotator"

    def setup(self):
        self.seen = []

    def required_columns(self):
        return ("OS",)

    def annotate_ip(self, ip, flows):
        self.seen.append(str(ip.ip_addr))
        ip.add_annotation(self.name, Annotation(None, None, flows["OS"].iloc[0], None, None))


class FlagDetector(Detector):
    name = "flag_detector"

    def detect(self, ip, flows):
        return {"detected": bool(flows["NAT"].any())}


def write_flows(path, rows):
    """Write flows given as (minute, ip, os, nat) tuples."""

    flows = [
        {
            "TIME_FIRST": (START + pd.Timedelta(minutes=minute)).isoformat(),
            "SRC_IP": ip,
            "SRC_PORT": 1000,
            "DST_PORT": 443,
            "OS": os_family,
            "NAT": nat,
        }
        for minute, ip, os_family, nat in rows
    ]
    pd.DataFrame(flows).to_csv(path, index=False)


def module_config(**daf):
    config = daf_config(group_annotator={}, os_annotator={}, flag_detector={})
    config["daf"].update(daf)
    return config


def modules_for(config):
    return [GroupAnnotator(config), OSAnnotator(config), FlagDetector(config)]


def run_daf(dataset, config, modules):
    arg = argparse.Namespace(dataset=str(dataset), reannotation=None, d=",", logfile=False)
    DAFApplication(arg, config, modules).create_runner().run()


def test_annotate_dataset(tmp_path):
    dataset = tmp_path / "flows.csv"
    write_flows(dataset, [(0, "10.0.0.1", "linux", False), (1, "10.0.0.2", "windows", False)])
    config = module_config()

    run_daf(dataset, config, modules_for(config))

    annotated = pd.read_csv(tmp_path / "flows_annotated.csv")
    assert annotated["os_family"].tolist() == ["linux", "windows"]
    assert annotated["group"].tolist() == ["end-device", "end-device"]


def test_windowed_run(tmp_path):
    dataset = tmp_path / "flows.csv"
    write_flows(
        dataset,
        [
            (0, "10.0.0.1", "linux", False),
            (1, "10.0.0.2", "windows", True),
            (16, "10.0.0.1", "linux", False),
            (17, "10.0.0.2", "windows", False),
            (31, "10.0.0.1", "windows", False),
        ],
    )
    windowing = {"enabled": True, "type": "time", "size": "15min", "timestamp_field": "TIME_FIRST"}
    config = module_config(windowing=windowing)
    modules = modules_for(config)

    run_daf(dataset, config, modules)

    # IP modules run once, flow modules in every window
    assert modules[0].calls == {"10.0.0.1": 1, "10.0.0.2": 1}
    assert modules[1].seen.count("10.0.0.1") == 3
    # 10.0.0.2 is flagged in the first window and skipped later
    assert modules[1].seen.count("10.0.0.2") == 1
    ip_data = {ip["ip_addr"]: ip for ip in json.loads((tmp_path / "flows_ip_data.json").read_text())}
    assert ip_data["10.0.0.1"]["annotations"]["os_annotator"]["os_family"] == "linux"


def test_ip_both_source_and_destination(tmp_path):
    dataset = tmp_path / "flows.csv"
    write_flows(dataset, [(0, "10.0.0.1", "linux", False), (1, "10.0.0.2", "windows", False)])
    flows = pd.read_csv(dataset)
    flows["DST_IP"] = ["10.0.0.2", "10.0.0.1"]
    flows.to_csv(dataset, index=False)
    config = module_config(dst_ip_field="DST_IP")
    modules = modules_for(config)

    run_daf(dataset, config, modules)

    assert modules[0].calls == {"10.0.0.1": 1, "10.0.0.2": 1}
    annotation_list = pd.read_csv(tmp_path / "flows_ip_annotation_list.csv")
    assert annotation_list["ip_address"].tolist() == ["10.0.0.1", "10.0.0.2"]
