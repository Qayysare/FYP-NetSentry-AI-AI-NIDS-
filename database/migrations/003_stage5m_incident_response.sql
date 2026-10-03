-- Stage 5M: additive human investigation, mitigation, and verification fields.
USE ai_nids;

ALTER TABLE incidents
    MODIFY status ENUM('New', 'Assigned', 'Investigating', 'Resolved', 'Closed') NOT NULL DEFAULT 'New',
    ADD COLUMN investigation_findings TEXT NULL AFTER notes,
    ADD COLUMN mitigation_taken TEXT NULL AFTER investigation_findings,
    ADD COLUMN handled_by INT UNSIGNED NULL AFTER mitigation_taken,
    ADD COLUMN handled_at TIMESTAMP NULL AFTER handled_by,
    ADD COLUMN verified_by INT UNSIGNED NULL AFTER handled_at,
    ADD COLUMN verified_at TIMESTAMP NULL AFTER verified_by,
    ADD COLUMN verification_remarks TEXT NULL AFTER verified_at,
    ADD CONSTRAINT fk_incident_handler FOREIGN KEY (handled_by) REFERENCES users(user_id) ON DELETE SET NULL,
    ADD CONSTRAINT fk_incident_verifier FOREIGN KEY (verified_by) REFERENCES users(user_id) ON DELETE SET NULL;
