"""Tests of merging the annotations of one IP."""

from annotation import Annotation
from ip import IP, MERGE_FAIL_LABEL


def test_conflicting_annotators():
    ip = IP("10.0.0.1")
    for name, os_family in [("a", "windows"), ("b", "windows"), ("c", "linux"), ("d", "linux")]:
        ip.add_annotation(name, Annotation(None, None, os_family, None, None))

    ip.perform_annotation(min_annotators_count=1)

    assert ip.final_annotation.os_family is None
    assert ip.multi_device[0][0] == MERGE_FAIL_LABEL
