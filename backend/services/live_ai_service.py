"""Coordinate existing Stage 4 AI components for a completed live capture."""
from __future__ import annotations

from collections import deque
from queue import Empty, Full, Queue
import threading
import time
from typing import Any

from ml.predictor import PredictionInputError
from services.flow_aggregator import BidirectionalFlowAggregator
from services.device_observation import PassiveDeviceObserver
from services.threat_persistence import ThreatPersistenceError, persist_malicious_predictions
from services.threat_priority import ThreatPriorityError, assess_threat
from services.tshark_service import TSharkService


class LiveAIAnalysisError(RuntimeError):
    """Raised when completed live flows cannot be analysed safely."""


SUPPORTED_CLASSES = ("BENIGN", "DDoS", "FTP-Patator", "PortScan", "SSH-Patator")
SEVERITIES = ("Informational", "Medium", "High", "Critical")


class ContinuousMonitoringSession:
    """Bounded near-real-time flow analysis for one active capture session.

    TShark calls :meth:`submit_packet` from its reader thread. A single worker
    owns the incremental aggregator, so flow state is never mutated by Flask
    request handlers. Completed flows only are passed to the existing model.
    """

    _STOP = object()

    def __init__(
        self,
        app: Any,
        predictor: Any,
        flow_timeout_seconds: int,
        dedup_window_seconds: int,
        max_active_flows: int,
        max_results: int,
        max_queue: int,
        poll_seconds: float,
    ):
        if predictor is None:
            raise LiveAIAnalysisError("The AI prediction service is unavailable.")
        self.app = app
        self.predictor = predictor
        self.dedup_window_seconds = dedup_window_seconds
        self.poll_seconds = max(float(poll_seconds), 0.5)
        self.aggregator = BidirectionalFlowAggregator(flow_timeout_seconds, max_active_flows)
        self.queue: Queue = Queue(maxsize=max_queue)
        self.results: deque[dict[str, Any]] = deque(maxlen=max_results)
        self._lock = threading.RLock()
        self._worker: threading.Thread | None = None
        self._accepting_packets = False
        self._running = False
        self._next_result_id = 1
        self.started_at: float | None = None
        self.packets_captured = 0
        self.dropped_queue_packets = 0
        self.completed_flows = 0
        self.prediction_count = 0
        self.malicious_flow_count = 0
        self.stored_threat_count = 0
        self.duplicate_suppressed_count = 0
        self.processing_error = False
        self.device_observer = PassiveDeviceObserver(app.config["DEVICE_OBSERVATION_UPDATE_SECONDS"])

    def start(self) -> None:
        with self._lock:
            if self._running:
                raise LiveAIAnalysisError("Monitoring is already active.")
            self._running = True
            self._accepting_packets = True
            self.started_at = time.time()
            self._worker = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name="ai-nids-flow-monitor",
            )
            self._worker.start()

    def submit_packet(self, packet: dict[str, Any]) -> None:
        """Accept one TShark packet without blocking its reader thread."""
        with self._lock:
            if not self._accepting_packets:
                return
            self.packets_captured += 1
        try:
            self.queue.put_nowait(packet)
        except Full:
            with self._lock:
                self.dropped_queue_packets += 1

    def _record_completed_flow(self, flow: dict[str, Any]) -> None:
        """Predict, assess and persist one completed flow without stopping monitoring."""
        try:
            prediction = self.predictor.predict_flow(flow)
            enriched = {**prediction, **assess_threat(prediction["classification"], prediction["confidence"], flow)}
        except (PredictionInputError, KeyError, ThreatPriorityError, ValueError):
            self.app.logger.warning("A completed monitoring flow could not be predicted and was skipped.")
            with self._lock:
                self.processing_error = True
            return

        persistence = {"stored_threat_count": 0, "duplicate_suppressed_count": 0}
        try:
            # Database helpers use Flask's application context. The model stays
            # loaded once on the application and is not recreated in this worker.
            with self.app.app_context():
                persistence = persist_malicious_predictions([enriched], self.dedup_window_seconds)
        except ThreatPersistenceError:
            self.app.logger.exception("A monitored malicious flow could not be persisted")
            with self._lock:
                self.processing_error = True

        with self._lock:
            enriched["result_id"] = self._next_result_id
            self._next_result_id += 1
            self.results.append(enriched)
            self.prediction_count += 1
            if enriched["classification"] != "BENIGN":
                self.malicious_flow_count += 1
            self.stored_threat_count += persistence["stored_threat_count"]
            self.duplicate_suppressed_count += persistence["duplicate_suppressed_count"]

    def _process_completed(self, flows: list[dict[str, Any]]) -> None:
        for flow in flows:
            with self._lock:
                self.completed_flows += 1
            self._record_completed_flow(flow)

    def _worker_loop(self) -> None:
        try:
            while True:
                try:
                    item = self.queue.get(timeout=self.poll_seconds)
                except Empty:
                    self._process_completed(self.aggregator.finalize_expired())
                    continue
                try:
                    if item is self._STOP:
                        self._process_completed(self.aggregator.finalize_all())
                        return
                    with self.app.app_context():
                        self.device_observer.observe_packet(item)
                    self._process_completed(self.aggregator.add_packet(item))
                finally:
                    self.queue.task_done()
        except Exception:
            self.app.logger.exception("Continuous monitoring worker stopped unexpectedly")
            with self._lock:
                self.processing_error = True
        finally:
            with self._lock:
                self._accepting_packets = False
                self._running = False

    def stop(self) -> dict[str, Any]:
        """Drain queued packets, flush active flows and wait for the one worker."""
        with self._lock:
            self._accepting_packets = False
            worker = self._worker
            running = self._running
        if running and worker:
            # Queue ordering guarantees that packets accepted before stop are
            # aggregated before the final flow flush marker.
            try:
                self.queue.put(self._STOP, timeout=5)
            except Full as error:
                raise LiveAIAnalysisError("Monitoring analysis queue could not be stopped cleanly.") from error
            worker.join(timeout=max(10.0, self.poll_seconds * 3))
            if worker.is_alive():
                raise LiveAIAnalysisError("Monitoring analysis did not stop cleanly.")
        return self.snapshot(0)

    def snapshot(self, after_result_id: int = 0) -> dict[str, Any]:
        """Return safe bounded counters and results newer than a client cursor."""
        with self._lock:
            new_results = [dict(item) for item in self.results if item["result_id"] > after_result_id]
            class_summary = {label: 0 for label in SUPPORTED_CLASSES}
            severity_summary = {label: 0 for label in SEVERITIES}
            for item in self.results:
                class_summary[item["classification"]] += 1
                severity_summary[item["severity"]] += 1
            return {
                "running": self._running,
                "worker_running": bool(self._worker and self._worker.is_alive()),
                "started_at": self.started_at,
                "packets_captured": self.packets_captured,
                "active_flows": self.aggregator.active_flow_count,
                "completed_flows": self.completed_flows,
                "prediction_count": self.prediction_count,
                "malicious_flow_count": self.malicious_flow_count,
                "stored_threat_count": self.stored_threat_count,
                "duplicate_suppressed_count": self.duplicate_suppressed_count,
                "dropped_queue_packets": self.dropped_queue_packets,
                "dropped_new_flow_packets": self.aggregator.dropped_new_flow_packets,
                "ai_flows": new_results,
                "latest_result_id": self._next_result_id - 1,
                "class_summary": class_summary,
                "severity_summary": severity_summary,
                "processing_error": self.processing_error,
            }


def analyse_completed_live_capture(
    packets: list[dict[str, Any]], predictor: Any, flow_timeout_seconds: int, dedup_window_seconds: int
) -> dict[str, Any]:
    """Flush one bounded capture batch through the shared Stage 4 pipeline.

    The packet list remains separate from the flow-level result. Flow feature
    creation is delegated to the existing Stage 4B bidirectional aggregator;
    the supplied predictor is the single instance held by the Flask app.
    """
    if predictor is None:
        raise LiveAIAnalysisError("The AI prediction service is unavailable.")
    try:
        flows = TSharkService.aggregate_bidirectional(packets, flow_timeout_seconds)
    except Exception as error:
        raise LiveAIAnalysisError("Completed live flows could not be generated.") from error

    try:
        predictions = predictor.predict_flows(flows)
    except PredictionInputError as error:
        raise LiveAIAnalysisError("Completed live flow data is not valid for AI prediction.") from error
    except Exception as error:
        raise LiveAIAnalysisError("Live AI prediction could not be completed.") from error

    try:
        enriched = [
            {**prediction, **assess_threat(prediction["classification"], prediction["confidence"], flow)}
            for flow, prediction in zip(flows, predictions)
        ]
    except (KeyError, ThreatPriorityError) as error:
        raise LiveAIAnalysisError("A live AI result could not be evaluated by the threat policy.") from error

    try:
        persistence = persist_malicious_predictions(enriched, dedup_window_seconds)
    except ThreatPersistenceError as error:
        raise LiveAIAnalysisError("Live AI threats could not be stored.") from error

    class_summary = {label: 0 for label in SUPPORTED_CLASSES}
    severity_summary = {label: 0 for label in SEVERITIES}
    for prediction in enriched:
        class_summary[prediction["classification"]] += 1
        severity_summary[prediction["severity"]] += 1

    return {
        "ai_flow_count": len(flows),
        "ai_flows": enriched,
        "class_summary": class_summary,
        "severity_summary": severity_summary,
        "malicious_flow_count": sum(item["classification"] != "BENIGN" for item in enriched),
        "requires_attention_count": sum(item["priority"] != "Monitor" for item in enriched),
        **persistence,
    }
