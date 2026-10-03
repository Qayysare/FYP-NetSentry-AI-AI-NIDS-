-- AI-NIDS Stage 2 seed data. All records are simulated for demonstration only.
USE ai_nids;

INSERT INTO users (full_name, username, email, password_hash, role) VALUES
('System Administrator', 'admin', 'admin@ai-nids.local', 'pbkdf2:sha256:600000$ai-nids-demo$2db0b37361cf232abbd0d8e087d61ce8a098a3e45f853c5408e6d2c2548f5ee1', 'admin'),
('Security Analyst', 'analyst', 'analyst@ai-nids.local', 'pbkdf2:sha256:600000$ai-nids-demo$2db0b37361cf232abbd0d8e087d61ce8a098a3e45f853c5408e6d2c2548f5ee1', 'analyst');
-- TEST-ONLY fixture account hashes. Do not load these accounts into a LAN deployment.

INSERT INTO network_traffic (source_ip, destination_ip, source_port, destination_port, protocol, packet_count, bytes_transferred, timestamp) VALUES
('192.168.1.12', '8.8.8.8', 53624, 53, 'DNS', 28, 18432, '2026-08-15 10:46:02'),
('203.0.113.45', '192.168.1.10', 44321, 80, 'TCP', 894, 1245184, '2026-08-15 10:45:50'),
('192.168.1.23', '172.217.194.102', 52110, 443, 'HTTPS', 123, 845824, '2026-08-15 10:45:44'),
('198.51.100.18', '192.168.1.1', 3189, 22, 'TCP', 156, 32512, '2026-08-15 10:45:39'),
('192.168.1.18', '192.168.1.255', 68, 67, 'UDP', 6, 2304, '2026-08-15 10:45:20'),
('192.168.1.44', '1.1.1.1', 49211, 443, 'HTTPS', 82, 598016, '2026-08-15 10:44:58');

INSERT INTO threats (traffic_id, attack_type, source_ip, destination_ip, severity, confidence_score, status, description, detected_at) VALUES
(2, 'Denial of Service', '203.0.113.45', '192.168.1.10', 'Critical', 94.80, 'New', 'Simulated high-volume connection pattern for Stage 2 demonstration.', '2026-08-15 10:42:00'),
(4, 'Port Scan', '198.51.100.18', '192.168.1.1', 'High', 87.40, 'Investigating', 'Simulated repeated connection attempts across monitored ports.', '2026-08-15 10:26:00'),
(NULL, 'Brute Force', '203.0.113.72', '192.168.1.23', 'High', 82.10, 'Resolved', 'Simulated repeated authentication failures.', '2026-08-15 09:58:00'),
(NULL, 'Suspicious Connection', '198.51.100.92', '192.168.1.12', 'Medium', 73.30, 'Investigating', 'Simulated unusual external connection pattern.', '2026-08-15 09:31:00'),
(NULL, 'Port Scan', '203.0.113.112', '192.168.1.1', 'Low', 61.20, 'Resolved', 'Simulated low-rate scan pattern.', '2026-08-15 09:08:00');

INSERT INTO devices (device_name, ip_address, mac_address, device_type, status, last_activity) VALUES
('Admin Laptop', '192.168.1.12', 'A4:5E:60:11:8C:2A', 'Laptop', 'Online', '2026-08-15 10:46:00'),
('Web Server', '192.168.1.10', '00:16:3E:43:71:11', 'Server', 'Online', '2026-08-15 10:45:00'),
('Main Router', '192.168.1.1', 'F8:1A:67:9D:08:52', 'Router', 'Online', '2026-08-15 10:46:00'),
('Research Desktop', '192.168.1.23', '98:FA:9B:61:CA:14', 'Desktop', 'Online', '2026-08-15 10:44:00'),
('Lab Sensor', '192.168.1.30', 'DC:A6:32:17:4D:8F', 'IoT', 'Idle', '2026-08-15 09:58:00'),
('Mobile Test Device', '192.168.1.44', '70:66:55:2C:0A:81', 'Mobile', 'Offline', '2026-08-14 18:02:00');

INSERT INTO security_logs (event_type, source, description, severity, status, created_at) VALUES
('Threat detected', 'Detection engine', 'Simulated Denial of Service traffic classified for review.', 'Critical', 'New', '2026-08-15 10:42:00'),
('Rule action', 'Firewall simulator', 'Demo rule marked a port scanning source for investigation.', 'High', 'Investigating', '2026-08-15 10:26:00'),
('Device connected', 'Network monitor', 'Admin Laptop appeared in the simulated device list.', 'Low', 'Recorded', '2026-08-15 10:15:00'),
('Threat detected', 'Detection engine', 'Repeated failed connection pattern classified as suspicious.', 'High', 'Investigating', '2026-08-15 09:58:00'),
('System event', 'Dashboard', 'Demo data refreshed by the user.', 'Low', 'Recorded', '2026-08-15 09:31:00');

INSERT INTO reports (report_title, report_date, total_events, total_threats, critical_alerts, most_common_attack) VALUES
('Weekly Network Security Report', '2026-08-15', 186, 12, 2, 'Port Scan');

INSERT INTO system_settings (setting_name, setting_value) VALUES
('system_name', 'AI-NIDS'), ('refresh_interval_seconds', '30'), ('critical_alerts_enabled', 'true'), ('show_demo_labels', 'true');
