-- SAFE security data platform tables for normalized telemetry and auditability.

CREATE TABLE IF NOT EXISTS detection_findings (
    finding_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    event_id TEXT,
    host_id TEXT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    tactic TEXT,
    technique TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence NUMERIC(5,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, finding_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    actor TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    integrity_hash TEXT
);

CREATE TABLE IF NOT EXISTS telemetry_lineage (
    lineage_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    source_event_id TEXT NOT NULL,
    derived_type TEXT NOT NULL,
    derived_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, lineage_id)
);

CREATE INDEX IF NOT EXISTS idx_detection_findings_tenant_rule
    ON detection_findings (tenant_id, rule_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_detection_findings_tenant_host
    ON detection_findings (tenant_id, host_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_time
    ON audit_log (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_lineage_source
    ON telemetry_lineage (tenant_id, source_event_id);
