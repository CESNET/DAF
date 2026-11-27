"""Tests of window iteration and window voting."""

import pandas as pd

from windows import TimeWindowIterator, WindowVoting


def test_voting():
    votes = ["linux", "linux", "windows", None]

    assert WindowVoting().vote(votes) == "linux"
    assert WindowVoting("threshold", 0.7).vote(votes) is None


def test_time_windows(tmp_path):
    start = pd.Timestamp("2026-01-01T10:00:00Z")
    times = [(start + pd.Timedelta(minutes=minute)).isoformat() for minute in [0, 1, 14, 15, 16, 31, 44, 50]]
    path = tmp_path / "flows.csv"
    pd.DataFrame({"TIME_FIRST": times, "SRC_IP": "10.0.0.1"}).to_csv(path, index=False)

    windows = list(TimeWindowIterator(path, ",", "TIME_FIRST", "15min", read_chunk_size=2))

    assert [len(window.flows) for window in windows] == [3, 2, 2, 1]
