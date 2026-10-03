"""Shared, conservative identity checks for passively observed local devices."""
from __future__ import annotations

import re


MAC_ADDRESS_PATTERN = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
ZERO_MAC = "00:00:00:00:00:00"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def normalise_unicast_mac(value: object) -> str | None:
    """Return a canonical individual MAC, or None for non-device identities."""
    if not isinstance(value, str):
        return None
    mac_address = value.strip().lower()
    if not MAC_ADDRESS_PATTERN.fullmatch(mac_address):
        return None
    if mac_address in {ZERO_MAC, BROADCAST_MAC}:
        return None
    # IEEE group/multicast addresses have bit 0 set in the first octet.
    if int(mac_address[:2], 16) & 1:
        return None
    return mac_address


def valid_unicast_mac_sql(column: str = "mac_address") -> str:
    """Return the MySQL predicate equivalent to ``normalise_unicast_mac``.

    ``column`` is supplied only by internal route code, not user input.
    """
    return (
        f"{column} REGEXP '^[0-9A-Fa-f]{{2}}(:[0-9A-Fa-f]{{2}}){{5}}$' "
        f"AND LOWER({column}) NOT IN ('{ZERO_MAC}', '{BROADCAST_MAC}') "
        f"AND (CONV(SUBSTRING({column}, 1, 2), 16, 10) & 1) = 0"
    )
