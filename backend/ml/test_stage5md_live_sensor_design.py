"""Static Stage 5M-D Live Sensor design contract; no capture or database use."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2]
def main():
 h=(ROOT/"pages"/"live-sensor.html").read_text(encoding="utf-8");j=(ROOT/"js"/"live-sensor.js").read_text(encoding="utf-8");c=(ROOT/"css"/"stage4.css").read_text(encoding="utf-8")
 r={"main_activity":all(x in h for x in ("Live AI Activity","live-activity-chart","Waiting for live AI predictions")),"chartjs":"chart.js" in h and "new Chart" in j,"real_session_data":all(x in j for x in ("status.ai_flows","status.class_summary","status.severity_summary","activityBuckets")),"no_demo_values":"demo" not in j.lower(),"classification_chart":"live-classification-chart" in h,"severity_chart":"live-severity-chart" in h and 'type: "bar"' in j,"responsive_containers":"live-activity-wrap" in c and "@media" in c,"controls_preserved":all(x in h for x in ("stop-sensor","monitoring-mode","monitoring-interface")),"table_preserved":"live-ai-body" in h}
 r["passed"]=all(r.values());print(json.dumps(r,indent=2));raise SystemExit(0 if r["passed"] else 1)
if __name__=="__main__":main()
