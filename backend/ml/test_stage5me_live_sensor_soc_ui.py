from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2]
def main():
 h=(ROOT/'pages/live-sensor.html').read_text(encoding='utf-8');j=(ROOT/'js/live-sensor.js').read_text(encoding='utf-8');c=(ROOT/'css/stage4.css').read_text(encoding='utf-8');r={'header':'sensor-hero' in h and 'sensor-icon' in h,'five_kpis':all(x in h for x in ('Packets Captured','Active Flows','Flows Analysed','AI Predictions','Threats Detected')),'line_series':'type:"line"' in j and all(x in j for x in ('BENIGN','PortScan','DDoS','SSH-Patator','FTP-Patator')),'real_session':'status.ai_flows' in j and 'buckets' in j,'session_reset':'started_at' in j and 'resetSession' in j,'severity':'live-severity-chart' in h,'table':'live-ai-body' in h,'responsive':'sensor-bottom-grid' in c,'controls':'stop-sensor' in h};r['passed']=all(r.values());print(json.dumps(r,indent=2));raise SystemExit(0 if r['passed'] else 1)
if __name__=='__main__':main()
