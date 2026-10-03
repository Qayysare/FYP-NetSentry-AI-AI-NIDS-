from pathlib import Path
import json
R=Path(__file__).resolve().parents[2]
def main():
 h=(R/'pages/examiner-demo.html').read_text(encoding='utf-8');j=(R/'js/examiner-demo.js').read_text(encoding='utf-8');x={'permanent_not_live_banner':'CONTROLLED DATASET REPLAY - NOT LIVE TRAFFIC' in h,'controls':all(v in h for v in ('replay-scenario','replay-speed','replay-start','replay-pause','replay-reset')),'actual_result_columns':all(v in h for v in ('Dataset Ground Truth','AI Prediction','Agreement')),'five_series':all(v in j for v in ('BENIGN','PortScan','SSH-Patator','FTP-Patator','DDoS')),'one_next_per_tick':'apiRequest("/api/replay/next"' in j and 'busy=true' in j,'no_live_wording':'No packets are transmitted' in h};x['passed']=all(x.values());print(json.dumps(x,indent=2));raise SystemExit(0 if x['passed'] else 1)
if __name__=='__main__':main()
