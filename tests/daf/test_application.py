"""Tests of the DAF command-line entry point."""

import shutil

import pandas as pd

from daf import main
from helpers import ROOT


def test_basic_example(tmp_path, monkeypatch):
    dataset = tmp_path / "example_dataset.csv"
    shutil.copy(ROOT / "examples" / "basic" / "example_dataset.csv", dataset)
    monkeypatch.chdir(ROOT / "src")

    main(["--config", "../examples/basic/daf_config_example.yml", "--dataset", str(dataset), "--logfile", "False"])

    annotated = pd.read_csv(tmp_path / "example_dataset_annotated.csv")
    assert len(annotated) == 865
    assert annotated["os_family"].notna().any()
