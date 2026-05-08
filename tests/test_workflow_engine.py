from xdr.workflow_engine import AnalystWorkflowEngine


def test_workflow_engine_returns_integral_workflows():
    engine = AnalystWorkflowEngine()
    workflow = engine.get_workflow("ransomware").to_dict()

    assert workflow["workflow_id"] == "ransomware"
    assert "confirm_mass_file_activity" in workflow["checklist"]
    assert "prepare_host_isolation_approval" in workflow["recommended_actions"]
    assert workflow["rollback_guidance"]


def test_workflow_engine_recommends_by_stage_and_behavior():
    engine = AnalystWorkflowEngine()

    assert engine.recommend_workflow(stage="credential_access").workflow_id == "credential_access"
    assert engine.recommend_workflow(behaviors=["beaconing"]).workflow_id == "beaconing"
    assert engine.recommend_workflow(behaviors=["scheduled_task persistence"]).workflow_id == "persistence"
    assert engine.recommend_workflow(severity="low").workflow_id == "triage"
