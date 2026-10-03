"""Static Stage 5M-B checks; deliberately does not access MySQL or capture."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2]
def main():
 incident=(ROOT/'pages/incidents.html').read_text(encoding='utf-8'); css=(ROOT/'css/incidents.css').read_text(encoding='utf-8'); route=(ROOT/'backend/routes/incidents.py').read_text(encoding='utf-8'); checks={'response_ui':all(x in incident for x in ('Investigation Findings','Mitigation / Resolution Taken','Verified By')),'print_signoff':all(x in incident for x in ('Handled By Signature','Verified By Signature','Official Stamp')) and '@page{size:A4 portrait' in css,'authenticated_handler':'handled_by = %s' in route and 'session["user_id"]' in route,'admin_verification':'Administrator verification is required' in route,'closed_status':'Closed' in route};checks['passed']=all(checks.values());print(json.dumps(checks,indent=2));raise SystemExit(0 if checks['passed'] else 1)
if __name__=='__main__':main()
