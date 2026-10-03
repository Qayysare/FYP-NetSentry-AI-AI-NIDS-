"""Static Stage 5M-I.3 relationship checks; no database writes or capture."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2]
def main():
 reports=(ROOT/'backend/services/report_service.py').read_text(encoding='utf-8');route=(ROOT/'backend/routes/reports.py').read_text(encoding='utf-8');incident_route=(ROOT/'backend/routes/incidents.py').read_text(encoding='utf-8');migration=(ROOT/'database/migrations/004_stage5mi3_report_incident_snapshots.sql').read_text(encoding='utf-8');checks={'snapshot_migration':'report_incident_snapshots' in migration and 'report_period_key' in migration,'snapshot_generation':'_store_snapshots' in reports and 'snapshot_storage_available' in reports,'general_and_incident_separate':'GENERAL THREAT ANALYSIS REPORT' in (ROOT/'pages/reports.html').read_text(encoding='utf-8') and 'INCIDENT RESOLUTION REPORT' in (ROOT/'pages/incidents.html').read_text(encoding='utf-8'),'report_detail_returns_snapshots':'incident_snapshots' in route,'threat_incident_link':'threat_id' in incident_route,'server_identity_preserved':'session["user_id"]' in incident_route,'no_duplicate_active_incident':"status <> 'Closed'" in incident_route};checks['passed']=all(checks.values());print(json.dumps(checks,indent=2));raise SystemExit(0 if checks['passed'] else 1)
if __name__=='__main__':main()
