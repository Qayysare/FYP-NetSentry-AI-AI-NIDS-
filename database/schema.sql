-- AI-NIDS Stage 2 schema. This database stores simulated/demo data only.
CREATE DATABASE IF NOT EXISTS ai_nids CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE ai_nids;

CREATE TABLE IF NOT EXISTS users (
    user_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'analyst', 'user') NOT NULL DEFAULT 'user',
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS network_traffic (
    traffic_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    source_port SMALLINT UNSIGNED NULL,
    destination_port SMALLINT UNSIGNED NULL,
    protocol VARCHAR(10) NOT NULL,
    packet_count INT UNSIGNED NOT NULL DEFAULT 0,
    bytes_transferred BIGINT UNSIGNED NOT NULL DEFAULT 0,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_traffic_timestamp (timestamp),
    INDEX idx_traffic_source_ip (source_ip),
    INDEX idx_traffic_destination_ip (destination_ip),
    INDEX idx_traffic_protocol (protocol)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS threats (
    threat_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    traffic_id INT UNSIGNED NULL,
    attack_type VARCHAR(80) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    severity ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL,
    confidence_score DECIMAL(5,2) NOT NULL COMMENT 'Demo score until Stage 4 AI/ML integration',
    status ENUM('New', 'Investigating', 'Resolved') NOT NULL DEFAULT 'New',
    description VARCHAR(500) NOT NULL,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_threat_traffic FOREIGN KEY (traffic_id) REFERENCES network_traffic(traffic_id) ON DELETE SET NULL,
    INDEX idx_threat_severity (severity),
    INDEX idx_threat_status (status),
    INDEX idx_threat_detected_at (detected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS devices (
    device_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    mac_address VARCHAR(17) NOT NULL UNIQUE,
    device_type ENUM('Laptop', 'Desktop', 'Server', 'Router', 'Mobile', 'IoT', 'Unknown') NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'Online',
    last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_device_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_logs (
    log_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(80) NOT NULL,
    source VARCHAR(100) NOT NULL,
    description VARCHAR(500) NOT NULL,
    severity ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL DEFAULT 'Low',
    status VARCHAR(30) NOT NULL DEFAULT 'Recorded',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_log_severity (severity),
    INDEX idx_log_status (status),
    INDEX idx_log_event_type (event_type),
    INDEX idx_log_created_at (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS reports (
    report_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    report_title VARCHAR(150) NOT NULL,
    report_kind VARCHAR(30) NOT NULL DEFAULT 'aggregate_period',
    report_period_key VARCHAR(10) NULL,
    report_period_label VARCHAR(40) NULL,
    report_period_start DATE NULL,
    report_period_end DATE NULL,
    report_date DATE NOT NULL,
    total_events INT UNSIGNED NOT NULL DEFAULT 0,
    total_threats INT UNSIGNED NOT NULL DEFAULT 0,
    critical_alerts INT UNSIGNED NOT NULL DEFAULT 0,
    most_common_attack VARCHAR(80) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_report_date (report_date)
) ENGINE=InnoDB;

-- New reports retain immutable incident-response snapshots. Existing reports
-- generated before this table was introduced remain valid aggregate records.
CREATE TABLE IF NOT EXISTS report_incident_snapshots (
    snapshot_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    report_id INT UNSIGNED NOT NULL,
    ticket_id INT UNSIGNED NULL,
    threat_id INT UNSIGNED NULL,
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
    CONSTRAINT fk_report_snapshot_report FOREIGN KEY (report_id) REFERENCES reports(report_id) ON DELETE CASCADE,
    INDEX idx_report_snapshot_report (report_id),
    INDEX idx_report_snapshot_ticket (ticket_id),
    INDEX idx_report_snapshot_threat (threat_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS system_settings (
    setting_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    setting_name VARCHAR(100) NOT NULL UNIQUE,
    setting_value VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS password_reset_requests (
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

CREATE TABLE IF NOT EXISTS incidents (
    ticket_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    threat_id INT UNSIGNED NOT NULL,
    assigned_to INT UNSIGNED NULL,
    assigned_by INT UNSIGNED NULL,
    status ENUM('New', 'Assigned', 'Investigating', 'Resolved', 'Closed') NOT NULL DEFAULT 'New',
    priority ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL DEFAULT 'Medium',
    notes VARCHAR(1000) NULL,
    investigation_findings TEXT NULL,
    mitigation_taken TEXT NULL,
    handled_by INT UNSIGNED NULL,
    handled_at TIMESTAMP NULL,
    verified_by INT UNSIGNED NULL,
    verified_at TIMESTAMP NULL,
    verification_remarks TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_incident_threat FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_assignee FOREIGN KEY (assigned_to) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_incident_assigner FOREIGN KEY (assigned_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_incident_handler FOREIGN KEY (handled_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_incident_verifier FOREIGN KEY (verified_by) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_incident_status (status),
    INDEX idx_incident_assignee (assigned_to)
) ENGINE=InnoDB;
