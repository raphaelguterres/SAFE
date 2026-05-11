"""Tests for xdr.asset_intelligence."""

import pytest

from xdr.asset_intelligence import (
    AssetClass, Environment, Sensitivity,
    AssetProfile,
    classify_asset, infer_environment, infer_sensitivity,
    compute_criticality, enrich_host,
)


class TestClassifyAsset:
    @pytest.mark.parametrize("name,expected", [
        ("DC01-PROD",          AssetClass.DOMAIN_CONTROLLER),
        ("dc-2019",            AssetClass.DOMAIN_CONTROLLER),
        ("adc-east",           AssetClass.DOMAIN_CONTROLLER),
        ("domain-controller",  AssetClass.DOMAIN_CONTROLLER),
        ("kdc01",              AssetClass.DOMAIN_CONTROLLER),
        ("db-mysql-prod-01",   AssetClass.DATABASE),
        ("postgres-replica",   AssetClass.DATABASE),
        ("mssql-001",          AssetClass.DATABASE),
        ("CEO-MAC-15",         AssetClass.EXECUTIVE_DEVICE),
        ("cfo-laptop",         AssetClass.EXECUTIVE_DEVICE),
        ("dev-john",           AssetClass.DEVELOPER_MACHINE),
        ("wks-dev-04",         AssetClass.DEVELOPER_MACHINE),
        ("srv-api-prod-02",    AssetClass.SERVER),
        ("web-frontend",       AssetClass.SERVER),
        ("wks-john-04",        AssetClass.WORKSTATION),
        ("desktop-alice",      AssetClass.WORKSTATION),
    ])
    def test_classify_by_hostname(self, name, expected):
        cls, _ = classify_asset({"host_id": "h1", "display_name": name})
        assert cls == expected

    def test_manual_override_wins(self):
        cls, reasons = classify_asset({
            "host_id": "h1",
            "display_name": "wks-john",  # would classify as workstation
            "asset_class": "critical_asset",
        })
        assert cls == AssetClass.CRITICAL_ASSET
        assert "manual_override" in reasons

    def test_invalid_manual_falls_through(self):
        cls, _ = classify_asset({"display_name": "DC01", "asset_class": "NOT_A_CLASS"})
        assert cls == AssetClass.DOMAIN_CONTROLLER  # falls back to hostname

    def test_role_field_used(self):
        cls, reasons = classify_asset({"display_name": "anonymous", "role": "database"})
        assert cls == AssetClass.DATABASE
        assert any("role=" in r for r in reasons)

    def test_tag_inference(self):
        cls, _ = classify_asset({"display_name": "anonymous", "tags": ["dc"]})
        assert cls == AssetClass.DOMAIN_CONTROLLER

        cls, _ = classify_asset({"display_name": "anonymous", "tags": ["executive"]})
        assert cls == AssetClass.EXECUTIVE_DEVICE

    def test_unknown_when_no_signal(self):
        cls, reasons = classify_asset({"host_id": "h1", "display_name": "random-thing"})
        assert cls == AssetClass.UNKNOWN
        assert "no_signal" in reasons

    def test_non_dict_returns_unknown(self):
        cls, _ = classify_asset("not a dict")
        assert cls == AssetClass.UNKNOWN
        cls, _ = classify_asset(None)
        assert cls == AssetClass.UNKNOWN


class TestInferEnvironment:
    @pytest.mark.parametrize("host,expected", [
        ({"environment": "production"},      Environment.PRODUCTION),
        ({"environment": "STAGING"},         Environment.STAGING),
        ({"tags": ["prod"]},                  Environment.PRODUCTION),
        ({"tags": ["qa", "uat"]},             Environment.STAGING),
        ({"tags": ["dev"]},                   Environment.DEVELOPMENT),
        ({"tags": ["lab", "sandbox"]},        Environment.LAB),
        ({"display_name": "api-prod-01"},     Environment.PRODUCTION),
        ({"display_name": "web-staging-02"},  Environment.STAGING),
        ({"display_name": "srv-dev-04"},      Environment.DEVELOPMENT),
        ({"display_name": "what"},            Environment.UNKNOWN),
    ])
    def test_environment_inference(self, host, expected):
        host.setdefault("host_id", "h1")
        assert infer_environment(host) == expected


class TestInferSensitivity:
    def test_explicit_field_wins(self):
        assert infer_sensitivity({"sensitivity": "restricted"}, AssetClass.WORKSTATION) == Sensitivity.RESTRICTED

    def test_tag_makes_restricted(self):
        assert infer_sensitivity({"tags": ["pii"]}, AssetClass.WORKSTATION) == Sensitivity.RESTRICTED
        assert infer_sensitivity({"tags": ["payroll"]}, AssetClass.WORKSTATION) == Sensitivity.RESTRICTED

    def test_class_defaults(self):
        assert infer_sensitivity({}, AssetClass.DOMAIN_CONTROLLER) == Sensitivity.CONFIDENTIAL
        assert infer_sensitivity({}, AssetClass.DATABASE)          == Sensitivity.CONFIDENTIAL
        assert infer_sensitivity({}, AssetClass.EXECUTIVE_DEVICE)  == Sensitivity.CONFIDENTIAL
        assert infer_sensitivity({}, AssetClass.SERVER)            == Sensitivity.INTERNAL
        assert infer_sensitivity({}, AssetClass.WORKSTATION)       == Sensitivity.INTERNAL


class TestComputeCriticality:
    def test_workstation_dev_low(self):
        score, impact = compute_criticality(AssetClass.WORKSTATION, Environment.DEVELOPMENT, Sensitivity.INTERNAL)
        assert score == 20
        assert "Low" in impact or "Minimal" in impact

    def test_dc_prod_restricted_caps_at_100(self):
        score, impact = compute_criticality(AssetClass.DOMAIN_CONTROLLER, Environment.PRODUCTION, Sensitivity.RESTRICTED)
        assert score == 100
        assert "Critical" in impact

    def test_lab_penalizes(self):
        s1, _ = compute_criticality(AssetClass.SERVER, Environment.PRODUCTION, Sensitivity.INTERNAL)
        s2, _ = compute_criticality(AssetClass.SERVER, Environment.LAB,        Sensitivity.INTERNAL)
        assert s2 < s1

    def test_sensitive_tag_boost(self):
        s_no_tag, _ = compute_criticality(AssetClass.SERVER, Environment.PRODUCTION, Sensitivity.INTERNAL, tags=())
        s_pii,    _ = compute_criticality(AssetClass.SERVER, Environment.PRODUCTION, Sensitivity.INTERNAL, tags=("pii",))
        assert s_pii > s_no_tag

    def test_business_impact_thresholds(self):
        # 0..19  Minimal, 20..39 Low, 40..64 Medium, 65..84 High, 85+ Critical
        _, i_min  = compute_criticality(AssetClass.UNKNOWN,     Environment.LAB,         Sensitivity.PUBLIC)
        _, i_low  = compute_criticality(AssetClass.WORKSTATION, Environment.DEVELOPMENT, Sensitivity.INTERNAL)
        _, i_med  = compute_criticality(AssetClass.SERVER,      Environment.DEVELOPMENT, Sensitivity.INTERNAL)
        _, i_hi   = compute_criticality(AssetClass.SERVER,      Environment.PRODUCTION,  Sensitivity.CONFIDENTIAL)
        _, i_crit = compute_criticality(AssetClass.DATABASE,    Environment.PRODUCTION,  Sensitivity.RESTRICTED)
        assert "Minimal" in i_min
        assert "Low" in i_low
        assert "Medium" in i_med
        assert "High" in i_hi
        assert "Critical" in i_crit


class TestEnrichHost:
    def test_full_dc_prod(self):
        p = enrich_host({"host_id": "h1", "display_name": "DC01-PROD",
                         "platform": "Windows Server 2019", "owner": "infra-team"})
        assert p.asset_class == AssetClass.DOMAIN_CONTROLLER
        assert p.environment == Environment.PRODUCTION
        assert p.sensitivity == Sensitivity.CONFIDENTIAL
        assert p.criticality_score >= 90
        assert p.owner == "infra-team"

    def test_dev_machine_low_critical(self):
        p = enrich_host({"host_id": "h2", "display_name": "wks-john-laptop", "tags": ["dev"]})
        assert p.asset_class == AssetClass.DEVELOPER_MACHINE
        assert p.environment == Environment.DEVELOPMENT
        assert p.criticality_score < 50

    def test_pii_tagged_db_capped_critical(self):
        p = enrich_host({"host_id": "h3", "display_name": "db-mysql-prod-01",
                         "tags": ["prod", "pii"]})
        assert p.asset_class == AssetClass.DATABASE
        assert p.sensitivity == Sensitivity.RESTRICTED
        assert p.criticality_score == 100

    def test_to_dict_round_trip(self):
        p = enrich_host({"host_id": "h1", "display_name": "DC01"})
        d = p.to_dict()
        assert d["host_id"] == "h1"
        assert d["asset_class"] == "domain_controller"
        assert "criticality_score" in d
        assert isinstance(d["tags"], list)

    def test_empty_input_returns_unknown_profile(self):
        p = enrich_host({})
        assert p.host_id == ""
        assert p.asset_class == AssetClass.UNKNOWN
        assert p.criticality_score >= 0

    def test_non_dict_returns_empty_profile(self):
        p = enrich_host(None)
        assert p.host_id == ""
        assert p.asset_class == AssetClass.UNKNOWN

    def test_never_mutates_input(self):
        host = {"host_id": "h1", "display_name": "DC01"}
        original = dict(host)
        _ = enrich_host(host)
        assert host == original
