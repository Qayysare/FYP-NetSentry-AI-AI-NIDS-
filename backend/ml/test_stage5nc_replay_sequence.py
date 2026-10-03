from pathlib import Path
import sys,json
from collections import Counter
R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/'backend'))
from services.controlled_replay_service import load_test_data,scenario_rows,MIXED_SOC_SEED,MIXED_COMPOSITION
def main():
 rows=scenario_rows(load_test_data(),'MIXED');labels=[r['Label'] for r in rows];round_robin=['BENIGN','PortScan','SSH-Patator','FTP-Patator','DDoS']*20;j=(R/'js/examiner-demo.js').read_text(encoding='utf-8');x={'mixed_100':len(rows)==100,'composition':Counter(labels)==MIXED_COMPOSITION,'unique_rows':len({r['_replay_row_id'] for r in rows})==100,'deterministic':labels==[r['Label'] for r in scenario_rows(load_test_data(),'MIXED')],'irregular':labels!=round_robin,'fixed_seed':MIXED_SOC_SEED==20250514,'rolling_window':'TIMELINE_WINDOW=35' in j,'timings':all(v in j for v in ('slow:1500','normal:750','fast:300')),'progress':'replay-progress-text' in (R/'pages/examiner-demo.html').read_text(encoding='utf-8'),'no_restricted_imports':all(v not in (R/'backend/services/controlled_replay_service.py').read_text() for v in ('TShark','persist_malicious','database'))};x['passed']=all(x.values());print(json.dumps({**x,'first_20':labels[:20]},indent=2));raise SystemExit(0 if x['passed'] else 1)
if __name__=='__main__':main()
