"""Controlled Replay regression: actual app routing, held-out data, and isolation."""
from pathlib import Path
import sys, json
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'backend'))
from app import create_app
from services.controlled_replay_service import CLASS_ORDER, RUNTIME_FEATURE_COLUMNS, load_test_data, scenario_rows

def client(app, user):
 c=app.test_client()
 with c.session_transaction() as s:s.update(user_id=user,username=f'user{user}',role='admin')
 return c
def main():
 data=load_test_data();app=create_app();app.config['TESTING']=True;c1=client(app,1);c2=client(app,2)
 with patch('routes.controlled_replay.ControlledReplayManager.start', wraps=app.extensions.setdefault('controlled_replay_manager', __import__('services.controlled_replay_service',fromlist=['ControlledReplayManager']).ControlledReplayManager()).start) as starter:
  anonymous=app.test_client().get('/api/replay/scenarios');routes={str(r):r.methods for r in app.url_map.iter_rules()};starts={key:c1.post('/api/replay/start',json={'scenario':key,'speed':'normal'}).get_json()['data'] for key in ('NORMAL','PORTSCAN','SSH','FTP','DDOS','MIXED')};c1.post('/api/replay/start',json={'scenario':'SSH','speed':'fast'});event=c1.post('/api/replay/next').get_json()['data']['event'];other=c2.get('/api/replay/status').get_json()['data'];reset=c1.post('/api/replay/reset');
 result={'uses_test_csv':str((ROOT/'datasets/processed/test.csv'))==str(__import__('services.controlled_replay_service',fromlist=['TEST_DATA_PATH']).TEST_DATA_PATH),'never_uses_train_csv':'train.csv' not in (ROOT/'backend/services/controlled_replay_service.py').read_text(),'required_20_features':all(x in data.columns for x in RUNTIME_FEATURE_COLUMNS) and len(RUNTIME_FEATURE_COLUMNS)==20,'label_required':'Label' in data.columns,'deterministic':scenario_rows(data,'SSH')[:2]==scenario_rows(data,'SSH')[:2],'scenario_labels':all(set(row['Label'] for row in scenario_rows(data,key))==({label} if key!='MIXED' else set(CLASS_ORDER)) for key,label in {'NORMAL':'BENIGN','PORTSCAN':'PortScan','SSH':'SSH-Patator','FTP':'FTP-Patator','DDOS':'DDoS','MIXED':'x'}.items()),'actual_predictor_and_policy':event and {'ground_truth','prediction','confidence','severity','priority','recommended_action','correct'}<=set(event),'session_isolated':other.get('total_replayed')==0,'reset_volatile':reset.status_code==200,'unsupported_scenario':c1.post('/api/replay/start',json={'scenario':'BAD','speed':'normal'}).status_code==400,'unsupported_speed':c1.post('/api/replay/start',json={'scenario':'SSH','speed':'turbo'}).status_code==400,'authentication':anonymous.status_code==401,'actual_app_blueprint':'/api/replay/next' in routes and 'POST' in routes['/api/replay/next'],'no_restricted_imports':all(name not in (ROOT/'backend/services/controlled_replay_service.py').read_text() for name in ('TShark','persist_malicious','device_observation','security_log','database','reports','incidents'))};result['passed']=all(result.values());print(json.dumps(result,indent=2));raise SystemExit(0 if result['passed'] else 1)
if __name__=='__main__':main()
