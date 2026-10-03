"""Stage 5O-D2 device identity checks using mocks only; no database rows change."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from services.device_identity import normalise_unicast_mac, valid_unicast_mac_sql  # noqa: E402
from services.device_observation import PassiveDeviceObserver  # noqa: E402


def observed_endpoints(packet: dict) -> list[tuple[str, str]]:
    observer = PassiveDeviceObserver(minimum_update_seconds=1)
    with patch.object(PassiveDeviceObserver, "_upsert", return_value=True) as upsert:
        observer.observe_packet(packet)
    return [call.args for call in upsert.call_args_list]


def main() -> None:
    valid_source = {"source_ip": "192.168.56.103", "source_mac": "08:00:27:83:71:A3", "destination_ip": "192.168.56.255", "destination_mac": "ff:ff:ff:ff:ff:ff"}
    all_zero = {"source_ip": "192.168.56.103", "source_mac": "00:00:00:00:00:00"}
    multicast = {"source_ip": "192.168.56.103", "source_mac": "01:00:5e:00:00:fb"}
    malformed = {"source_ip": "192.168.56.103", "source_mac": "08:00:27:83:71"}
    suffix_255 = {"source_ip": "10.100.135.255", "source_mac": "14:ac:60:18:ce:21"}
    source_calls = observed_endpoints(valid_source)
    devices_route = (PROJECT_ROOT / "backend" / "routes" / "devices.py").read_text(encoding="utf-8")
    list_devices_source = devices_route.split('@devices_bp.get("/<int:device_id>")', maxsplit=1)[0]
    dashboard_route = (PROJECT_ROOT / "backend" / "routes" / "dashboard.py").read_text(encoding="utf-8")
    devices_html = (PROJECT_ROOT / "pages" / "connected-devices.html").read_text(encoding="utf-8")
    devices_js = (PROJECT_ROOT / "js" / "devices.js").read_text(encoding="utf-8")
    result = {
        "valid_private_unicast_accepted": normalise_unicast_mac("08:00:27:83:71:A3") == "08:00:27:83:71:a3",
        "valid_source_survives_broadcast_destination": source_calls == [("192.168.56.103", "08:00:27:83:71:a3")],
        "broadcast_not_observed": observed_endpoints({"source_ip": "192.168.56.255", "source_mac": "ff:ff:ff:ff:ff:ff"}) == [],
        "all_zero_rejected": normalise_unicast_mac(all_zero["source_mac"]) is None and observed_endpoints(all_zero) == [],
        "multicast_rejected": normalise_unicast_mac(multicast["source_mac"]) is None and observed_endpoints(multicast) == [],
        "malformed_rejected": normalise_unicast_mac(malformed["source_mac"]) is None and observed_endpoints(malformed) == [],
        "virtualbox_mac_accepted": normalise_unicast_mac("0a:00:27:00:00:13") == "0a:00:27:00:00:13",
        "ip_suffix_255_allowed": observed_endpoints(suffix_255) == [("10.100.135.255", "14:ac:60:18:ce:21")],
        "shared_sql_rule_used": "valid_unicast_mac_sql" in devices_route and "valid_unicast_mac_sql" in dashboard_route,
        "api_filters_before_limit": "WHERE {valid_identity} ORDER BY last_activity DESC LIMIT 200" in devices_route,
        "dashboard_is_active_and_uncapped": "last_activity >= DATE_SUB(CURRENT_TIMESTAMP" in dashboard_route and "LIMIT 200" not in dashboard_route,
        "no_historical_device_mutation": all(token not in list_devices_source for token in ("DELETE FROM devices", "UPDATE devices")),
        "accurate_ui_wording": "Recently Observed Local Devices" in devices_html and "No local devices have been observed during authorised monitoring yet." in devices_js,
        "no_synthetic_fallback": "sampleDevices" not in devices_js,
        "sql_predicate_rejects_known_values": "00:00:00:00:00:00" in valid_unicast_mac_sql() and "& 1" in valid_unicast_mac_sql(),
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
