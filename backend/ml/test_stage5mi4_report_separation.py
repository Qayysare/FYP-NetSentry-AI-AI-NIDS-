"""Static Stage 5M-I.4 contract checks without database writes."""
from pathlib import Path
import json
R=Path(__file__).resolve().parents[2]
def main():
 route=(R/'backend/routes/incidents.py').read_text(encoding='utf-8');page=(R/'pages/incidents.html').read_text(encoding='utf-8');js=(R/'js/incidents.js').read_text(encoding='utf-8');css=(R/'css/incidents.css').read_text(encoding='utf-8');reports=(R/'pages/reports.html').read_text(encoding='utf-8')
 x={'separate_workflows':'GENERAL THREAT ANALYSIS REPORT' in reports and 'INCIDENT RESOLUTION REPORT' in page,'authorized_endpoint':'/<int:ticket_id>/report' in route and 'login_required' in route,'resolved_gate':'{"Resolved", "Closed"}' in route,'correct_linkage':'INC-${r.ticket_id}' in js and 'THR-${r.threat_id}' in js,'pending_verification':'Pending administrator verification' in route and 'Pending Administrator Verification' in page,'actual_handler':'handled_username' in route and 'handled_at' in route,'no_assignment_invention':'Assignment Timestamp: Unavailable' in js,'review_and_print':'review-incident-report' in page and 'print-incident-report' in page,'incident_print_only':'.incident-workspace,.action-button' in css and '@page{size:A4 portrait' in css};x['passed']=all(x.values());print(json.dumps(x,indent=2));raise SystemExit(0 if x['passed'] else 1)
if __name__=='__main__':main()
