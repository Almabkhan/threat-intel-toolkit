#!/usr/bin/env python3
"""
Threat Intelligence Analyzer - Educational Tool
Analyzes and correlates IOCs and threat feeds
"""

import json
from datetime import datetime
from collections import Counter

class ThreatAnalyzer:
    def __init__(self):
        self.iocs = {}
        self.feeds = {}
        self.correlations = []
        
    def load_data(self, ioc_file='iocs.json', feed_file='threat_feeds.json'):
        """Load IOCs and threat feeds"""
        # Load IOCs
        try:
            with open(ioc_file, 'r') as f:
                ioc_data = json.load(f)
                self.iocs = ioc_data.get('iocs', {})
                print(f"[+] Loaded IOCs from {ioc_file}")
        except FileNotFoundError:
            print(f"[!] {ioc_file} not found")
        
        # Load feeds
        try:
            with open(feed_file, 'r') as f:
                feed_data = json.load(f)
                self.feeds = feed_data.get('feeds', {})
                print(f"[+] Loaded threat feeds from {feed_file}")
        except FileNotFoundError:
            print(f"[!] {feed_file} not found")
    
    def analyze_iocs(self):
        """Analyze IOCs for patterns"""
        print("\n" + "="*60)
        print("📊 IOC ANALYSIS")
        print("="*60)
        
        if not self.iocs:
            print("No IOCs loaded")
            return
        
        total_iocs = sum(len(v) for v in self.iocs.values())
        print(f"\nTotal IOCs: {total_iocs}")
        
        for category, items in self.iocs.items():
            print(f"\n{category.upper()}: {len(items)} items")
            if items and len(items) > 0:
                print(f"  Sample: {items[0]}")
    
    def analyze_feeds(self):
        """Analyze threat feeds for trends"""
        print("\n" + "="*60)
        print("📊 THREAT FEED ANALYSIS")
        print("="*60)
        
        if not self.feeds:
            print("No threat feeds loaded")
            return
        
        for category, items in self.feeds.items():
            print(f"\n{category.upper()}: {len(items)} threats")
            if items and len(items) > 0:
                sample = items[0]
                if 'name' in sample:
                    print(f"  Latest: {sample['name']}")
                elif 'target' in sample:
                    print(f"  Latest: {sample['target']}")
    
    def find_correlations(self):
        """Find correlations between IOCs and feeds"""
        print("\n" + "="*60)
        print("🔄 THREAT CORRELATION ANALYSIS")
        print("="*60)
        
        correlations = []
        
        # Check IP correlations
        if 'ip_addresses' in self.iocs and 'botnet' in self.feeds:
            for ip in self.iocs['ip_addresses']:
                for botnet in self.feeds['botnet']:
                    if botnet.get('c2') == ip:
                        correlations.append({
                            'type': 'Botnet C2',
                            'ioc': ip,
                            'threat': botnet['name'],
                            'confidence': 'high'
                        })
        
        # Check malware name correlations
        if 'hashes' in self.iocs and 'malware' in self.feeds:
            for malware in self.feeds['malware']:
                # Simplified correlation
                correlations.append({
                    'type': 'Malware',
                    'ioc': f"Hash for {malware['name']}",
                    'threat': malware['name'],
                    'confidence': 'medium'
                })
        
        self.correlations = correlations
        
        if correlations:
            print(f"\n[+] Found {len(correlations)} correlations:")
            for corr in correlations[:5]:
                print(f"\n  • {corr['type']}")
                print(f"    IOC: {corr['ioc']}")
                print(f"    Threat: {corr['threat']}")
                print(f"    Confidence: {corr['confidence']}")
        else:
            print("\n[!] No correlations found")
        
        return correlations
    
    def generate_threat_report(self):
        """Generate comprehensive threat report"""
        print("\n" + "="*60)
        print("📑 THREAT INTELLIGENCE REPORT")
        print("="*60)
        print(f"Generated: {datetime.now().isoformat()}")
        
        self.analyze_iocs()
        self.analyze_feeds()
        self.find_correlations()
        
        # Save report
        report = {
            'timestamp': datetime.now().isoformat(),
            'ioc_summary': {k: len(v) for k, v in self.iocs.items()},
            'feed_summary': {k: len(v) for k, v in self.feeds.items()},
            'correlations': self.correlations
        }
        
        filename = f'threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to {filename}")

def main():
    print("="*60)
    print("🔬 THREAT INTELLIGENCE ANALYZER - Educational Tool")
    print("="*60)
    
    analyzer = ThreatAnalyzer()
    
    print("\n📌 Options:")
    print("1. Load and analyze data")
    print("2. Find correlations")
    print("3. Generate full report")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == "1":
        analyzer.load_data()
        analyzer.analyze_iocs()
        analyzer.analyze_feeds()
    elif choice == "2":
        analyzer.load_data()
        analyzer.find_correlations()
    elif choice == "3":
        analyzer.load_data()
        analyzer.generate_threat_report()
    else:
        print("[!] Invalid choice")

if __name__ == "__main__":
    main()