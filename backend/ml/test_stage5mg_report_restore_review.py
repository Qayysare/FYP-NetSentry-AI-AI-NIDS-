from pathlib import Path
import json
R=Path(__file__).resolve().parents[2]
def main():
 h=(R/'pages/reports.html').read_text(encoding='utf-8');j=(R/'js/reports.js').read_text(encoding='utf-8');x={'summary_cards':all(v in h for v in ('report-events','report-threats','report-critical','report-high','report-medium','report-unresolved')),'generate':'generate-report' in h,'history':'reports-history-body' in h,'print':'print-report' in h,'general_type':'GENERAL THREAT ANALYSIS REPORT' in h,'history_before_review':h.index('reports-history-body')<h.index('report-preview'),'review':'data-review' in j,'no_engineer_form':'textarea' not in h,'general_analysis':all(v in h for v in ('Attack Classification Analysis','Severity Analysis','Threat Status Analysis'))};x['passed']=all(x.values());print(json.dumps(x,indent=2));raise SystemExit(0 if x['passed'] else 1)
if __name__=='__main__':main()
