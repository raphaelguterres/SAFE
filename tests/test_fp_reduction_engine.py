from xdr.fp_reduction_engine import FalsePositiveReductionEngine


def test_fp_engine_never_hides_critical_credential_access_alerts():
    assessment = FalsePositiveReductionEngine().assess_alert(
        {
            "severity": "critical",
            "summary": "credential dumping indicator against lsass",
            "command_line": "procdump lsass.exe",
        },
        baseline={"known_good_command": True},
        historical_frequency=100,
        signer_trust="trusted",
    ).to_dict()

    assert assessment["classification"] == "likely_true_positive"
    assert assessment["preserve_alert"] is True
    assert assessment["suppressible"] is False
    assert assessment["false_positive_probability"] <= 0.25


def test_fp_engine_marks_repetitive_trusted_low_signal_as_likely_benign_context_only():
    assessment = FalsePositiveReductionEngine().assess_alert(
        {"severity": "low", "summary": "routine inventory command"},
        baseline={"known_good_command": True},
        historical_frequency=50,
        signer_trust="enterprise_trusted",
    )

    assert assessment.classification == "likely_benign"
    assert assessment.preserve_alert is True
    assert assessment.suppressible is True
