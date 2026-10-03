"""Passive, bounded device observation from TShark packet endpoint metadata."""
from __future__ import annotations

import ipaddress
import time

from mysql.connector import Error

from database import database_cursor
from services.device_identity import normalise_unicast_mac


def _local_ipv4(address):
    """Accept only RFC1918 IPv4 addresses; never treat public peers as devices."""
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return False
    return isinstance(value, ipaddress.IPv4Address) and any(
        value in ipaddress.ip_network(network)
        for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )


class PassiveDeviceObserver:
    """Observe each local IP/MAC endpoint at a modest interval during capture."""

    def __init__(self, minimum_update_seconds=60):
        self.minimum_update_seconds = max(int(minimum_update_seconds), 1)
        self._last_observed = {}

    def observe_packet(self, packet):
        observed = 0
        for prefix in ("source", "destination"):
            ip_address = packet.get(f"{prefix}_ip")
            mac_address = normalise_unicast_mac(packet.get(f"{prefix}_mac"))
            if not (_local_ipv4(ip_address) and mac_address):
                continue
            key = (str(ip_address), mac_address)
            now = time.monotonic()
            if now - self._last_observed.get(key, 0) < self.minimum_update_seconds:
                continue
            if self._upsert(*key):
                self._last_observed[key] = now
                observed += 1
        return observed

    @staticmethod
    def _upsert(ip_address, mac_address):
        """Update a stable existing device, or add a truthfully unknown observed one."""
        try:
            with database_cursor() as (_connection, cursor):
                cursor.execute(
                    "SELECT device_id FROM devices WHERE ip_address = %s OR mac_address = %s LIMIT 1",
                    (ip_address, mac_address),
                )
                existing = cursor.fetchone()
                if existing:
                    cursor.execute(
                        "UPDATE devices SET last_activity = CURRENT_TIMESTAMP, status = 'Active' "
                        "WHERE device_id = %s",
                        (existing["device_id"],),
                    )
                else:
                    cursor.execute(
                        "INSERT INTO devices (device_name, ip_address, mac_address, device_type, status) "
                        "VALUES (%s, %s, %s, %s, 'Active')",
                        ("Observed device", ip_address, mac_address, "Unknown"),
                    )
            return True
        except Error:
            return False
