-- Run once against an existing ai_nids Stage 2 database after backing it up.
USE ai_nids;

ALTER TABLE users
    ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE AFTER role,
    ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE AFTER must_change_password;

ALTER TABLE network_traffic
    MODIFY source_port SMALLINT UNSIGNED NULL,
    MODIFY destination_port SMALLINT UNSIGNED NULL;

CREATE TABLE password_reset_requests (
    request_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status ENUM('Pending', 'Approved', 'Rejected', 'Completed') NOT NULL DEFAULT 'Pending',
    approved_by INT UNSIGNED NULL,
    approved_at TIMESTAMP NULL,
    CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_reset_approver FOREIGN KEY (approved_by) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_reset_status (status)
) ENGINE=InnoDB;

CREATE TABLE incidents (
    ticket_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    threat_id INT UNSIGNED NOT NULL,
    assigned_to INT UNSIGNED NULL,
    assigned_by INT UNSIGNED NULL,
    status ENUM('New', 'Assigned', 'Investigating', 'Resolved') NOT NULL DEFAULT 'New',
    priority ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL DEFAULT 'Medium',
    notes VARCHAR(1000) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_incident_threat FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_assignee FOREIGN KEY (assigned_to) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_incident_assigner FOREIGN KEY (assigned_by) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_incident_status (status),
    INDEX idx_incident_assignee (assigned_to)
) ENGINE=InnoDB;
