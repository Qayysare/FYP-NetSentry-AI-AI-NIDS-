from pathlib import Path
import json
R=Path(__file__).resolve().parents[2]
def main():
 h=(R/'pages/reports.html').read_text(encoding='utf-8');j=(R/'js/reports.js').read_text(encoding='utf-8');c=(R/'css/reports.css').read_text(encoding='utf-8');x={'no_view':'data-view' not in j,'review':'data-review' in j,'print_workflow':'window.print()' in j and 'printButton.disabled=true' in j,'a4':'@page{size:A4 portrait' in c,'header':'GENERAL THREAT ANALYSIS REPORT' in h,'print_only_manual_area':'general-print-signoff' in h and '.general-print-signoff{display:none}' in c,'print_hide':all(v in c for v in ('.sidebar','#app-header','.report-history','#report-dashboard')),'generate':'generate-report' in h,'history':'reports-history-body' in h};x['passed']=all(x.values());print(json.dumps(x,indent=2));raise SystemExit(0 if x['passed'] else 1)
if __name__=='__main__':main()
