#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: nat_detector.py
Description: Detect NAT devices with a trained machine-learning model.
"""

import logging
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from config import Requirement
from core import Detector
from dataset import FlowDataset
from detectors.common import ProbabilityClassifier

logger = logging.getLogger("NAT detector")


class NATClassifier(ProbabilityClassifier[pd.DataFrame, pd.Series]):
    """Aggregate and classify all source-flow rows belonging to one IP."""

    def __init__(
        self,
        model: Any,
        aggregation: dict[str, tuple[str, str]],
        *,
        positive_label: Any = 1,
        threshold: float = 0.5,
    ) -> None:
        self.model = model
        self.aggregation = aggregation
        self.positive_label = positive_label
        super().__init__(threshold)

    @property
    def feature_names(self) -> tuple[str, ...]:
        """Return model feature names in their aggregation order."""

        return tuple(self.aggregation)

    @property
    def required_columns(self) -> tuple[str, ...]:
        """Return the raw flow columns required by the aggregation."""

        return tuple(dict.fromkeys(column for column, _ in self.aggregation.values()))

    def aggregate(self, flows: pd.DataFrame) -> pd.Series:
        """Aggregate one IP's flows into one model feature row."""

        features = flows.groupby(lambda _: 0).agg(**self.aggregation).iloc[0]
        features.name = None
        return features

    def predict_probability(self, features: pd.Series) -> float:
        """Predict the positive-class probability for one feature row."""

        probabilities = self.model.predict_proba(features.to_frame().T)[0]
        positive_index = list(self.model.classes_).index(self.positive_label)
        return float(probabilities[positive_index])


def _load_classifier(config: dict) -> NATClassifier:
    """Create the configured NAT classifier."""

    if "nat_detector" not in config or "model_path" not in config["nat_detector"]:
        logger.error("NAT detector model_path not found in configuration file")
        raise RuntimeError("NAT Detector:: Configuration or model_path not found")

    try:
        import joblib
    except ImportError as error:
        raise RuntimeError(
            "Loading a NAT classifier requires the nat_detector dependencies"
        ) from error

    detector_config = config["nat_detector"]
    model_path = Path(detector_config["model_path"]).expanduser()
    classifier = joblib.load(model_path)
    classifier_type = type(classifier)
    if (
        classifier_type.__module__ != NATClassifier.__module__
        or classifier_type.__qualname__ != NATClassifier.__qualname__
    ):
        raise TypeError("NAT model file must contain a NATClassifier")

    if "threshold" in detector_config:
        classifier.threshold = detector_config["threshold"]
    return classifier


def _load_feature_mapping(classifier: NATClassifier, config: dict) -> dict[str, str]:
    """Map the model's canonical raw fields to input dataset columns."""

    configured_mapping = config["nat_detector"].get("feature_mapping", {})
    if not isinstance(configured_mapping, dict):
        raise TypeError("NAT detector feature_mapping must be a mapping")

    unknown_fields = set(configured_mapping).difference(classifier.required_columns)
    if unknown_fields:
        unknown = ", ".join(sorted(unknown_fields))
        raise ValueError(f"NAT detector feature_mapping contains unknown fields: {unknown}")

    invalid_fields = [
        field
        for field, column in configured_mapping.items()
        if not isinstance(column, str) or not column
    ]
    if invalid_fields:
        invalid = ", ".join(sorted(invalid_fields))
        raise ValueError(f"NAT detector feature_mapping requires column names for: {invalid}")

    return {field: configured_mapping.get(field, field) for field in classifier.required_columns}


def _map_flow_columns(flows: pd.DataFrame, feature_mapping: dict[str, str]) -> pd.DataFrame:
    """Expose configured dataset columns under their canonical model names."""

    missing_columns = [column for column in feature_mapping.values() if column not in flows.columns]
    if missing_columns:
        missing = ", ".join(dict.fromkeys(missing_columns))
        raise KeyError(f"NAT detector input is missing mapped columns: {missing}")

    if all(field == column for field, column in feature_mapping.items()):
        return flows

    mapped_flows = flows.copy()
    for field, column in feature_mapping.items():
        mapped_flows[field] = flows[column]
    return mapped_flows


class NATDetector(Detector):
    """Detect NAT devices with a trained model or by the number of unique TTL values and source ports.

    If ``model_path`` is configured, the flows of every IP are classified by the
    :class:`NATClassifier` stored in the file, see :func:`_load_classifier`. Otherwise
    an IP is flagged as a possible multi-device if its flows contain at least
    ``min_unique_ttl`` distinct TTL counts and ``min_unique_src_ports`` distinct
    source ports. Zero values are ignored.
    """

    name = "nat_detector"
    description = "NAT detection"
    evidence_label = "NAT_detector"
    REQUIREMENTS = (
        Requirement("field", str, required_if={"model_path": None}),
        Requirement("min_unique_ttl", int, default=5, minimum=0),
        Requirement("min_unique_src_ports", int, default=500, minimum=0),
    )
    DAF_REQUIREMENTS = (Requirement("src_port_field", str), Requirement("src_ip_field", str))
    classifier = None
    feature_mapping = None

    def setup(self) -> None:
        """Load the classifier and its feature mapping if ``model_path`` is configured."""

        if self.config.get("model_path") is not None:
            self.classifier = _load_classifier(self.full_config)
            self.feature_mapping = _load_feature_mapping(self.classifier, self.full_config)

    def required_columns(self) -> tuple:
        """Return the mapped model columns, or the TTL and source port columns.

        Returns
        -------
        tuple
            Names of the required columns.
        """

        if self.classifier is not None:
            return tuple(dict.fromkeys(self.feature_mapping.values()))
        return (self.config["field"], self.daf_config["src_port_field"])

    def detect_all(self, ip_addresses: list, flows_by_ip) -> Optional[dict]:
        """Count unique TTL values and source ports of all IP addresses at once.

        With a model, every IP is classified separately by :meth:`detect`.

        Parameters
        ----------
        ip_addresses : list
            Target IP objects.
        flows_by_ip : Mapping
            Flows keyed by source IP address string.

        Returns
        -------
        dict or None
            Results of :meth:`detect` keyed by IP address string, None with a model.
        """

        if self.classifier is not None:
            return None

        dataset = FlowDataset.coerce(flows_by_ip, self.daf_config["src_ip_field"])
        flows = dataset.flows
        src = dataset.src_ip_field
        ttl_field = self.config["field"]
        port_field = self.daf_config["src_port_field"]

        ttl = flows.loc[flows[ttl_field] != 0, [src, ttl_field]]
        ttl_counts = ttl.groupby([src, ttl_field]).size()
        unique_ttl = ttl_counts.groupby(level=0).nunique()
        ports = flows.loc[flows[port_field] != 0, [src, port_field]]
        unique_ports = ports.groupby(src)[port_field].nunique()
        unique_ttl = {str(key): int(value) for key, value in unique_ttl.items()}
        unique_ports = {str(key): int(value) for key, value in unique_ports.items()}

        results = {}
        for ip in ip_addresses:
            key = str(ip.ip_addr)
            if key not in dataset:
                continue
            unique_ttl_values = unique_ttl.get(key, 0)
            unique_src_ports = unique_ports.get(key, 0)
            results[key] = {
                "detected": unique_ttl_values >= self.config["min_unique_ttl"]
                and unique_src_ports >= self.config["min_unique_src_ports"],
                "unique_ttl_values": unique_ttl_values,
                "unique_src_ports": unique_src_ports,
            }
        return results

    def detect(self, ip, flows) -> dict:
        """Classify one IP address, or count its unique TTL values and source ports.

        Parameters
        ----------
        ip : IP
            IP object to check.
        flows : pd.DataFrame
            Flows of the IP.

        Returns
        -------
        dict
            ``detected`` decision with the probability or the counted values.
        """

        if self.classifier is not None:
            mapped_ip_flows = _map_flow_columns(flows, self.feature_mapping)
            is_nat, probability = self.classifier.classify(mapped_ip_flows)
            return {
                "detected": is_nat,
                "probability": probability,
                "threshold": self.classifier.threshold,
                "model": type(self.classifier.model).__name__,
            }

        ttl_values = flows[self.config["field"]]
        src_ports = flows[self.daf_config["src_port_field"]]
        ttl_values = ttl_values[ttl_values != 0]
        src_ports = src_ports[src_ports != 0]

        unique_ttl_values = int(ttl_values.value_counts().nunique())
        unique_src_ports = int(src_ports.nunique())

        return {
            "detected": unique_ttl_values >= self.config["min_unique_ttl"]
            and unique_src_ports >= self.config["min_unique_src_ports"],
            "unique_ttl_values": unique_ttl_values,
            "unique_src_ports": unique_src_ports,
        }
