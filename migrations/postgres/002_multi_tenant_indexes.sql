-- Tenant-scoped indexes for pilot-scale query performance.

CREATE INDEX IF NOT EXISTS idx_hosts_tenant_status
    ON hosts (tenant_id, status, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_hosts_tenant_risk
    ON hosts (tenant_id, risk_score DESC, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_tenant_time
    ON security_events (tenant_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_tenant_host_time
    ON security_events (tenant_id, host_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_tenant_severity
    ON security_events (tenant_id, severity, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status_severity
    ON incidents (tenant_id, status, severity, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_actions_tenant_host_status
    ON agent_actions (tenant_id, host_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_payload_gin
    ON security_events USING GIN (payload);
