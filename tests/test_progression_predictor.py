from xdr.progression_predictor import AttackProgressionPredictor


def test_progression_predictor_forecasts_credential_access_from_persistence_and_c2():
    prediction = AttackProgressionPredictor().predict(
        active_stages=["persistence", "command_and_control"],
        behaviors=["beaconing"],
    ).to_dict()

    assert prediction["predicted_next_stage"] == "credential_access"
    assert prediction["confidence"] >= 0.7
    assert "identity" in prediction["recommended_prevention"]


def test_progression_predictor_uses_safe_monitoring_when_evidence_is_weak():
    prediction = AttackProgressionPredictor().predict(active_stages=[], behaviors=[]).to_dict()

    assert prediction["predicted_next_stage"] == "monitoring"
    assert prediction["confidence"] < 0.5
