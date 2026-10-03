"""Safe, limited wrapper around the configured TShark executable."""
from __future__ import annotations

import os
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

FIELD_NAMES = [
    "packet_number", "timestamp", "source_mac", "destination_mac", "source_ip",
    "destination_ip", "protocol", "display_protocol", "source_port", "destination_port", "packet_length",
    "payload_length", "tcp_fin",
]
FIELD_ARGS = [
    "-T", "fields", "-E", "header=n", "-E", "separator=\t", "-E", "quote=d",
    "-e", "frame.number", "-e", "frame.time_epoch", "-e", "eth.src", "-e", "eth.dst",
    "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
    "-e", "ip.proto", "-e", "ipv6.nxt", "-e", "_ws.col.Protocol", "-e", "tcp.srcport", "-e", "udp.srcport",
    "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "frame.len",
    "-e", "tcp.len", "-e", "udp.length", "-e", "tcp.flags.fin",
]


class TSharkError(RuntimeError):
    pass


class TSharkService:
    def __init__(self, executable: str):
        self.executable = Path(executable)
        self.process: subprocess.Popen | None = None
        self.interface_id: str | None = None
        self.records: list[dict] = []
        self.packet_callback = None
        self.reader_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _base_command(self) -> list[str]:
        if not self.executable.is_file():
            raise TSharkError("Configured TShark executable was not found.")
        return [str(self.executable)]

    def _run(self, arguments: list[str], timeout: int = 30) -> str:
        try:
            result = subprocess.run(self._base_command() + arguments, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TSharkError("TShark could not complete the requested operation.") from error
        if result.returncode != 0:
            raise TSharkError("TShark could not read the selected capture source.")
        return result.stdout

    def version(self) -> str:
        return self._run(["--version"], timeout=10).splitlines()[0]

    def interfaces(self) -> list[dict]:
        output = self._run(["-D"], timeout=15)
        interfaces = []
        for line in output.splitlines():
            match = re.match(r"^(\d+)\.\s+(.*)$", line.strip())
            if match:
                name = match.group(2)
                # Windows TShark commonly reports a NPF path followed by a
                # stable friendly adapter name in parentheses.
                friendly_match = re.search(r"\(([^()]+)\)\s*$", name)
                interfaces.append({
                    "id": match.group(1),
                    "name": name,
                    "friendly_name": friendly_match.group(1).strip() if friendly_match else None,
                })
        return interfaces

    @staticmethod
    def resolve_interface(configured_value: str, interfaces: list[dict]) -> dict | None:
        """Resolve a configured current ID or discovered human-friendly name.

        A numeric index can change after adapter/environment changes. This
        resolver deliberately uses only the metadata returned by the current
        TShark interface listing; it never stores a machine-specific GUID.
        """
        configured = str(configured_value or "").strip().casefold()
        if not configured:
            return None
        matches = [
            item for item in interfaces
            if configured in {
                str(item.get("id") or "").strip().casefold(),
                str(item.get("name") or "").strip().casefold(),
                str(item.get("friendly_name") or "").strip().casefold(),
            }
        ]
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _transport_protocol(ip_protocol: str, ipv6_next_header: str) -> str:
        """Return a stable L4 identity without using Wireshark display labels."""
        try:
            protocol_number = int(ip_protocol or ipv6_next_header)
        except (TypeError, ValueError):
            return "IP-UNKNOWN"
        return {6: "TCP", 17: "UDP"}.get(protocol_number, f"IP-{protocol_number}")

    @staticmethod
    def _packet_from_line(line: str) -> dict | None:
        values = [value.strip('"') for value in line.rstrip("\r\n").split("\t")]
        if len(values) < 19:
            return None
        source_ip, ipv6_source, destination_ip, ipv6_destination = values[4:8]
        source_port = values[11] or values[12] or None
        destination_port = values[13] or values[14] or None
        try:
            packet_length = int(values[15] or 0)
        except ValueError:
            packet_length = 0
        try:
            timestamp = datetime.fromtimestamp(float(values[1]), timezone.utc).isoformat() if values[1] else None
        except ValueError:
            timestamp = None
        def as_int(value):
            try:
                return int(value) if value else None
            except ValueError:
                return None
        tcp_payload_length = as_int(values[16])
        udp_length = as_int(values[17])
        # CICFlowMeter's selected byte features use transport payload bytes.
        payload_length = tcp_payload_length if tcp_payload_length is not None else max(0, (udp_length or 0) - 8)
        tcp_fin = values[18].strip().lower() in {"1", "true", "yes"}
        protocol = TSharkService._transport_protocol(values[8], values[9])
        return {
            "packet_number": as_int(values[0]), "timestamp": timestamp,
            "source_mac": values[2] or None, "destination_mac": values[3] or None,
            "source_ip": source_ip or ipv6_source or None,
            "destination_ip": destination_ip or ipv6_destination or None,
            # ``protocol`` is deliberately transport-level because it is used
            # by bidirectional flow identity. The separate display value is
            # retained only for packet display/debugging.
            "protocol": protocol, "display_protocol": values[10] or "Unknown",
            "source_port": as_int(source_port),
            "destination_port": as_int(destination_port), "packet_length": packet_length,
            "payload_length": payload_length, "tcp_fin": tcp_fin,
            "status": "Captured",
        }

    def analyse_file(self, capture_path: str, limit: int = 500) -> list[dict]:
        path = Path(capture_path)
        if path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise TSharkError("Only .pcap and .pcapng files are supported.")
        if not path.is_file():
            raise TSharkError("The selected capture file was not found.")
        output = self._run(["-r", str(path), "-c", str(limit)] + FIELD_ARGS, timeout=60)
        return [packet for line in output.splitlines() if (packet := self._packet_from_line(line))]

    def start(self, interface_id: str, packet_callback=None) -> None:
        allowed = {item["id"] for item in self.interfaces()}
        if interface_id not in allowed:
            raise TSharkError("Selected capture interface is not available.")
        with self._lock:
            if self.process and self.process.poll() is None:
                raise TSharkError("A capture is already running.")
            self.records = []
            self.interface_id = interface_id
            self.packet_callback = packet_callback
            self.process = subprocess.Popen(self._base_command() + ["-l", "-i", interface_id] + FIELD_ARGS, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            self.reader_thread = threading.Thread(target=self._read_output, daemon=True, name="ai-nids-tshark-reader")
            self.reader_thread.start()

    def _read_output(self) -> None:
        process = self.process
        if not process or not process.stdout:
            return
        for line in process.stdout:
            packet = self._packet_from_line(line)
            if packet:
                with self._lock:
                    if len(self.records) < 1000:
                        self.records.append(packet)
                    callback = self.packet_callback
                # The monitoring callback is deliberately outside the TShark
                # lock so bounded queue handling cannot block service status.
                if callback:
                    try:
                        callback(packet)
                    except Exception:
                        # A monitoring failure must not leave the TShark reader
                        # thread dead. The monitoring service records its error.
                        pass

    def stop(self) -> list[dict]:
        with self._lock:
            process = self.process
            if not process or process.poll() is not None:
                raise TSharkError("No capture is currently running.")
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        reader_thread = self.reader_thread
        if reader_thread and reader_thread is not threading.current_thread():
            reader_thread.join(timeout=2)
        with self._lock:
            self.process = None
            self.interface_id = None
            self.packet_callback = None
            self.reader_thread = None
            return list(self.records)

    def status(self) -> dict:
        with self._lock:
            active = bool(self.process and self.process.poll() is None)
            return {"running": active, "interface_id": self.interface_id if active else None, "packet_count": len(self.records)}

    @staticmethod
    def aggregate(records: list[dict]) -> list[dict]:
        flows: dict[tuple, dict] = {}
        for record in records:
            if not record["source_ip"] or not record["destination_ip"]:
                continue
            key = (record["source_ip"], record["destination_ip"], record["source_port"], record["destination_port"], record["protocol"])
            flow = flows.setdefault(key, {"source_ip": key[0], "destination_ip": key[1], "source_port": key[2], "destination_port": key[3], "protocol": key[4], "packet_count": 0, "bytes_transferred": 0})
            flow["packet_count"] += 1
            flow["bytes_transferred"] += record.get("packet_length", 0)
        return list(flows.values())

    @staticmethod
    def aggregate_bidirectional(records: list[dict], timeout_seconds: int) -> list[dict]:
        """Return Stage 4 flow features without changing Stage 3 summaries."""
        from services.flow_aggregator import aggregate_bidirectional_flows

        return aggregate_bidirectional_flows(records, timeout_seconds)
