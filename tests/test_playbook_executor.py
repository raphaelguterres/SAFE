from xdr.playbook_executor import DefensivePlaybookExecutor, PlaybookStepStatus


def test_playbook_executor_requires_approval_for_critical_actions_and_audits():
    executor = DefensivePlaybookExecutor()
    run = executor.create_run(
        tenant_id="tenant-a",
        playbook="isolate_host",
        target="host-1",
        requested_by="analyst",
        simulation_mode=True,
    )

    isolation = next(step for step in run.steps if step.action_type == "isolate_host")
    assert isolation.approval_required is True
    assert isolation.status == PlaybookStepStatus.WAITING_APPROVAL
    assert run.audit_log

    executor.approve_step(run, step_id=isolation.step_id, approver="admin")
    executed = executor.execute_ready_steps(run)
    assert executed
    assert all(step.simulation_result["mode"] == "simulation" for step in executed)
    assert any(item["event_type"] == "step_approved" for item in run.audit_log)


def test_playbook_executor_rollback_chain_is_available():
    executor = DefensivePlaybookExecutor()
    run = executor.create_run(
        tenant_id="tenant-a",
        playbook="network_containment_recommendation",
        target="host-1",
        requested_by="analyst",
    )
    for step in run.steps:
        if step.approval_required:
            executor.approve_step(run, step_id=step.step_id, approver="admin")
    executor.execute_ready_steps(run)
    rollbacks = executor.rollback(run, actor="admin")

    assert any(item["rollback_action"] == "remove_network_block" for item in rollbacks)
    assert run.status == "rolled_back"
