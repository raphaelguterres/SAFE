from safe_mode import SafeModeController


def test_safe_mode_enters_on_queue_pressure_and_suppresses_low_priority():
    controller = SafeModeController()
    state = controller.evaluate(health_status="degraded", queue_pressure=0.9)

    assert state.value == "safe_mode"
    low = controller.prioritize_event({"priority": "P3", "event_type": "debug"})
    critical = controller.prioritize_event({"priority": "P0", "event_type": "credential_access"})
    assert low.accepted is False
    assert critical.accepted is True


def test_safe_mode_reduces_p2_but_keeps_signal():
    controller = SafeModeController()
    controller.enter("test")

    decision = controller.prioritize_event({"priority": "P2", "event_type": "telemetry"})

    assert decision.accepted is True
    assert decision.reduced is True
