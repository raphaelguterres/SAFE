"""Tests for xdr.asset_intelligence."""

import pytest

from xdr.asset_intelligence import (
    AssetClass, Sensitivity, Environment, AssetProfile,
    classify_asset, detect_environment, score_criticality,
    business_impact_label, enrich_host,
)


class TestClassifyAsset:
    def test_returns_unknown_when_no_signal(self):
        assert classify_asset({}) == AssetClass.UNKNOWN
        assert classify_asset({"host_id": "h1"}) == AssetClass.UNKNOWN

    def test_classifies_domain_controller_by_hostname(self):
        assert classify_asset({"hostname": "WIN-DC-01"}) == AssetClass.DOMAIN_CONTROLLER
        assert classify_asset({"hostname": "domain-controller-east"}) == AssetClass.DOMAIN_CONTROLLER
        assert classify_asset({"hostname": "adctrl-prod"}) == AssetClass.DOMAIN_CONTROLLER

    def test_classifies_database(self):
        assert classify_asset({"hostname": "db-prod-mysql-01"}) == AssetClass.DATABASE
        assert classify_asset({"hostname": "pgsql-replica-02"}) == AssetClass.DATABASE
        assert classify_asset({"hostname": "mssql-cluster-1"}) == AssetClass.DATABASE

    def test_classifies_server(self):
        assert classify_asset({"hostname": "webapp-prod-01"}) == AssetClass.SERVER
        assert classify_asset({"hostname": "api-srv-03"}) == AssetClass.SERVER

    def test_classifies_workstation(self):
        assert classify_asset({"hostname": "WIN10-WKS-042"}) == AssetClass.WORKSTATION
        assert classify_asset({"hostname": "laptop-marketing-04"}) == AssetClass.WORKSTATION

    def test_classifies_dev_machine(self):
        assert classify_asset({"hostname": "devbox-bob"}) == AssetClass.DEV_MACHINE
        assert classify_asset({"hostname": "dev-runner-01"}) == AssetClass.DEV_MACHINE

    def test_classifies_executive(self):
        assert classify_asset({"hostname": "laptop-ceo-jose"}) == AssetClass.EXECUTIVE_DEVICE
        assert classify_asset({"hostname": "cfo-macbook"}) == AssetClass.EXECUTIVE_DEVICE

    def test_tag_override_wins_over_hostname(self):
        # hostname looks like a workstation, but tag says critical-asset
        h = {"hostname": "WIN-WKS-001", "tags": ["critical-asset"]}
        assert classify_asset(h) == AssetClass.CRITICAL_ASSET

    def test_explicit_role_field(self):
        assert classify_asset({"role": "database"}) == AssetClass.DATABASE
        assert classify_asset({"asset_class": "server"}) == AssetClass.SERVER

    def test_invalid_role_falls_back_to_hostname(self):
        h = {"role": "garbage", "hostname": "DC-01"}
        assert classify_asset(h) == AssetClass.DOMAIN_CONTROLLER

    def test_non_dict_safe(self):
        assert classify_asset(None) == AssetClass.UNKNOWN
        assert classify_asset("string") == AssetClass.UNKNOWN
        assert classify_asset([1, 2]) == AssetClass.UNKNOWN


class TestDetectEnvironment:
    def test_unknown_by_default(self):
        assert detect_environment({}) == Environment.UNKNOWN

    def test_explicit_environment_field(self):
        assert detect_environment({"environment": "prod"}) == Environment.PROD
        assert detect_environment({"environment": "production"}) == Environment.PROD
        assert detect_environment({"environment": "stg"}) == Environment.STAGING
        assert detect_environment({"environment": "dev"}) == Environment.DEV

    def test_tag_signals_environment(self):
        assert detect_environment({"tags": ["prod", "linux"]}) == Environment.PROD
        assert detect_environment({"tags": ["qa"]}) == Environment.STAGING

    def test_hostname_inference(self):
        assert detect_environment({"hostname": "app-prod-01"}) == Environment.PROD
        assert detect_environment({"hostname": "app-staging-02"}) == Environment.STAGING
        assert detect_environment({"hostname": "devbox"}) == Environment.DEV


class TestScoreCriticality:
    def test_domain_controller_prod_is_critical(self):
        p = AssetProfile("h1", AssetClass.DOMAIN_CONTROLLER, environment=Environment.PROD)
        assert score_criticality(p) >= 90

    def test_dev_machine_in_dev_is_low(self):
        p = AssetProfile("h1", AssetClass.DEV_MACHINE, environment=Environment.DEV)
        assert score_criticality(p) <= 15

    def test_environment_lowers_score(self):
        prod = AssetProfile("h1", AssetClass.SERVER, environment=Environment.PROD)
        dev  = AssetProfile("h1", AssetClass.SERVER, environment=Environment.DEV)
        assert score_criticality(prod) > score_criticality(dev)

    def test_sensitivity_bumps_score(self):
        public = AssetProfile("h1", AssetClass.SERVER, environment=Environment.PROD,
                              sensitivity=Sensitivity.PUBLIC)
        restricted = AssetProfile("h1", AssetClass.SERVER, environment=Environment.PROD,
                                  sensitivity=Sensitivity.RESTRICTED)
        assert score_criticality(restricted) > score_criticality(public)

    def test_score_clamped_to_100(self):
        # Force overshoot: critical asset + prod + restricted sensitivity
        p = AssetProfile("h1", AssetClass.CRITICAL_ASSET,
                         environment=Environment.PROD,
                         sensitivity=Sensitivity.RESTRICTED)
        score = score_criticality(p)
        assert 0 <= score <= 100


class TestBusinessImpactLabel:
    @pytest.mark.parametrize("score,label", [
        (0,     "low"),
        (15,    "low"),
        (35,    "medium"),
        (60,    "medium"),
        (65,    "high"),
        (80,    "high"),
        (85,    "critical"),
        (100,   "critical"),
    ])
    def test_bucket_boundaries(self, score, label):
        assert business_impact_label(score) == label


class TestEnrichHost:
    def test_returns_profile_with_host_id(self):
        p = enrich_host({"host_id": "h-123", "hostname": "WIN-DC-01"})
        assert p.host_id == "h-123"
        assert p.asset_class == AssetClass.DOMAIN_CONTROLLER

    def test_criticality_filled_in(self):
        p = enrich_host({"host_id": "h1", "hostname": "db-prod-01"})
        assert p.criticality_score >= 70
        assert p.business_impact in ("high", "critical")

    def test_unknown_host_safe(self):
        p = enrich_host({})
        assert p.host_id == ""
        assert p.asset_class == AssetClass.UNKNOWN

    def test_does_not_mutate_input(self):
        original = {"host_id": "h1", "hostname": "DC-01", "tags": ["prod"]}
        snapshot = dict(original)
        enrich_host(original)
        assert original == snapshot

    def test_non_dict_safe(self):
        p = enrich_host(None)
        assert p.host_id == ""

    def test_to_dict_serializable(self):
        import json
        p = enrich_host({"host_id": "h1", "hostname": "WIN-WKS-01"})
        d = p.to_dict()
        # Round-trip through JSON should not raise
        json.dumps(d)
        assert d["asset_class"] == "workstation"

    def test_tags_passed_through(self):
        p = enrich_host({"host_id": "h1", "tags": ["finance", "regulated"]})
        assert "finance" in p.tags
        assert "regulated" in p.tags

    def test_owner_passed_through(self):
        p = enrich_host({"host_id": "h1", "owner": "infra-team"})
        assert p.owner == "infra-team"
