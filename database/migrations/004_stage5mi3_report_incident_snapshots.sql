-- Stage 5M-I.3: persist period metadata and immutable incident-response
-- snapshots for newly generated aggregate reports. Run once manually in
-- phpMyAdmin after reviewing it; this migration is intentionally not automatic.
USE ai_nids;

ALTER TABLE reports
    ADD COLUMN report_kind VARCHAR(30) NOT NULL DEFAULT 'aggregate_period' AFTER report_title,
    ADD COLUMN report_period_key VARCHAR(10) NULL AFTER report_kind,
    ADD COLUMN report_period_label VARCHAR(40) NULL AFTER report_period_key,
    ADD COLUMN report_period_start DATE NULL AFTER report_period_label,
    ADD COLUMN report_period_end DATE NULL AFTER report_period_start;

CREATE TABLE report_incident_snapshots (
    snapshot_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    report_id INT UNSIGNED NOT NULL,
    ticket_id INT UNSIGNED NULL COMMENT 'Original incident ID at report generation',
    threat_id INT UNSIGNED NULL COMMENT 'Original threat ID at report generation',
    incident_status VARCHAR(20) NULL,
    attack_type VARCHAR(80) NULL,
    source_ip VARCHAR(45) NULL,
    destination_ip VARCHAR(45) NULL,
    severity VARCHAR(20) NULL,
    confidence_score DECIMAL(5,2) NULL,
    detected_at TIMESTAMP NULL,
    assigned_username VARCHAR(50) NULL,
    investigation_findings TEXT NULL,
    mitigation_taken TEXT NULL,
    handled_username VARCHAR(50) NULL,
    handled_at TIMESTAMP NULL,
    verified_username VARCHAR(50) NULL,
    verified_at TIMESTAMP NULL,
    verification_remarks TEXT NULL,
    snapshot_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_report_snapshot_report FOREIGN KEY (report_id)
        REFERENCES reports(report_id) ON DELETE CASCADE,
    INDEX idx_report_snapshot_report (report_id),
    INDEX idx_report_snapshot_ticket (ticket_id),
    INDEX idx_report_snapshot_threat (threat_id)
) ENGINE=InnoDB;
