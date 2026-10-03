-- Stage 5I: passive observation needs a neutral, non-guessed device type.
ALTER TABLE devices
    MODIFY device_type ENUM('Laptop', 'Desktop', 'Server', 'Router', 'Mobile', 'IoT', 'Unknown') NOT NULL;
