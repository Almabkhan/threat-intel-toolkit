#!/usr/bin/env python3
"""
Threat Intelligence Reporter - Educational Tool
Generates formatted threat intelligence reports
"""

import json
from datetime import datetime
import os

class ThreatReporter:
    def __init__(self):
        self.report_data = {}
        
    def load_latest_report(self):
        """Load the most recent threat report"""
        reports = [f for f in os.listdir('.') if f.startswith('threat_report_') and f.endswith('.json')]
        
        if not reports:
            print("[!] No threat reports found")
            return False
        
        latest = max(reports)
        with open(latest, 'r') as f:
            self.report_data = json.load(f)
        
        print(f"[+] Loaded report: {latest}")
        return True
    
    def generate_html_report(self):
        """Generate HTML format report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Threat Intelligence Report</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; }}
        .high {{ color: red; }}
        .medium {{ color: orange; }}
        .low {{ color: green; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>🔍 Threat Intelligence Report</h1>
    <p>Generated: {self.report_data.get('timestamp', 'Unknown')}</p>
    
    <div class="section">
        <h2>IOC Summary</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Count</th>
            </tr>
"""
        
        for category, count in self.report_data.get('ioc_summary', {}).items():
            html += f"""
            <tr>
                <td>{category}</td>
                <td>{count}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Threat Feed Summary</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Count</th>
            </tr>
"""
        
        for category, count in self.report_data.get('feed_summary', {}).items():
            html += f"""
            <tr>
                <td>{category}</td>
                <td>{count}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Correlations Found</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>IOC</th>
                <th>Threat</th>
                <th>Confidence</th>
            </tr>
"""
        
        for corr in self.report_data.get('correlations', []):
            html += f"""
            <tr>
                <td>{corr.get('type', '')}</td>
                <td>{corr.get('ioc', '')}</td>
                <td>{corr.get('threat', '')}</td>
                <td class="{corr.get('confidence', 'low')}">{corr.get('confidence', '')}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
</body>
</html>
"""
        
        filename = f'threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        with open(filename, 'w') as f:
            f.write(html)
        
        print(f"[+] HTML report saved to {filename}")
    
    def generate_markdown_report(self):
        """Generate Markdown format report"""
        md = f"# Threat Intelligence Report\n\n"
        md += f"**Generated:** {self.report_data.get('timestamp', 'Unknown')}\n\n"
        
        md += "## IOC Summary\n\n"
        md += "| Category | Count |\n"
        md += "|----------|-------|\n"
        for category, count in self.report_data.get('ioc_summary', {}).items():
            md += f"| {category} | {count} |\n"
        
        md += "\n## Threat Feed Summary\n\n"
        md += "| Category | Count |\n"
        md += "|----------|-------|\n"
        for category, count in self.report_data.get('feed_summary', {}).items():
            md += f"| {category} | {count} |\n"
        
        md += "\n## Correlations Found\n\n"
        md += "| Type | IOC | Threat | Confidence |\n"
        md += "|------|-----|--------|------------|\n"
        for corr in self.report_data.get('correlations', []):
            md += f"| {corr.get('type', '')} | {corr.get('ioc', '')} | {corr.get('threat', '')} | {corr.get('confidence', '')} |\n"
        
        filename = f'threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
        with open(filename, 'w') as f:
            f.write(md)
        
        print(f"[+] Markdown report saved to {filename}")
    
    def generate_summary(self):
        """Generate plain text summary"""
        print("\n" + "="*60)
        print("📋 THREAT INTELLIGENCE SUMMARY")
        print("="*60)
        print(f"Generated: {self.report_data.get('timestamp', 'Unknown')}\n")
        
        print("IOC Summary:")
        for category, count in self.report_data.get('ioc_summary', {}).items():
            print(f"  • {category}: {count}")
        
        print("\nThreat Feed Summary:")
        for category, count in self.report_data.get('feed_summary', {}).items():
            print(f"  • {category}: {count}")
        
        correlations = self.report_data.get('correlations', [])
        print(f"\nCorrelations: {len(correlations)} found")
        
        if correlations:
            print("\nTop Correlations:")
            for corr in correlations[:3]:
                print(f"  • {corr.get('type')}: {corr.get('ioc')} -> {corr.get('threat')}")

def main():
    print("="*60)
    print("📋 THREAT INTELLIGENCE REPORTER - Educational Tool")
    print("="*60)
    
    reporter = ThreatReporter()
    
    if not reporter.load_latest_report():
        print("\n[!] Run analyzer.py first to generate a report")
        return
    
    print("\n📌 Options:")
    print("1. Generate HTML report")
    print("2. Generate Markdown report")
    print("3. Show summary")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == "1":
        reporter.generate_html_report()
    elif choice == "2":
        reporter.generate_markdown_report()
    elif choice == "3":
        reporter.generate_summary()
    else:
        print("[!] Invalid choice")

if __name__ == "__main__":
    main()