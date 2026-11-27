"""Tests of the configuration requirements."""

import pytest

from config import ConfigError, Configurable, Requirement


class Example(Configurable):
    REQUIREMENTS = (
        Requirement("name", str),
        Requirement("count", int, default=1, maximum=10),
    )


def test_requirements():
    section = {"name": "x"}
    Example.check_config(section, "example")
    assert section == {"name": "x", "count": 1}

    with pytest.raises(ConfigError, match="example.name: missing required field"):
        Example.check_config({}, "example")
    with pytest.raises(ConfigError, match="example.count: must be at most 10"):
        Example.check_config({"name": "x", "count": 11}, "example")
