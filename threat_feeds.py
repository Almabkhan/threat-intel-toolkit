#!/usr/bin/env python3
"""
Threat Feeds Aggregator - Educational Tool
Aggregates and normalizes threat intelligence feeds
"""

import json
from datetime import datetime
import random

class ThreatFeedAggregator:
    def __init__(self):
        self.feeds = {
            'malware': [],
            'phishing': [],
            'botnet': [],
            'ransomware': []
        }
        
    def generate_feed_data(self):
        """Generate sample threat feed data"""
        print("[*] Generating threat feed data...")
        
        # Malware feeds
        self.feeds['malware'] = [
            {'name': 'Emotet', 'type': 'trojan', 'first_seen': '2024-01-15', 'risk': 'high'},
            {'name': 'TrickBot', 'type': 'banking malware', 'first_seen': '2024-01-20', 'risk': 'high'},
            {'name': 'Dridex', 'type': 'downloader', 'first_seen': '2024-02-01', 'risk': 'medium'},
            {'name': 'QakBot', 'type': 'banking trojan', 'first_seen': '2024-02-05', 'risk': 'high'},
            {'name': 'IcedID', 'type': 'loader', 'first_seen': '2024-02-10', 'risk': 'medium'}
        ]
        
        # Phishing feeds
        self.feeds['phishing'] = [
            {'target': 'banking', 'campaign': 'CapitalOne', 'first_seen': '2024-01-18', 'active': True},
            {'target': 'paypal', 'campaign': 'PayPal_2024', 'first_seen': '2024-01-25', 'active': True},
            {'target': 'amazon', 'campaign': 'Amazon_Prime', 'first_seen': '2024-02-03', 'active': False},
            {'target': 'microsoft', 'campaign': 'Office365', 'first_seen': '2024-02-08', 'active': True},
            {'target': 'google', 'campaign': 'Google_Docs', 'first_seen': '2024-02-12', 'active': True}
        ]
        
        # Botnet feeds
        self.feeds['botnet'] = [
            {'name': 'Mirai', 'c2': '185.142.53.100', 'size': 50000, 'first_seen': '2024-01-10'},
            {'name': 'QakBot', 'c2': '45.155.205.142', 'size': 15000, 'first_seen': '2024-01-22'},
            {'name': 'Emotet', 'c2': '197.45.132.88', 'size': 30000, 'first_seen': '2024-02-01'},
            {'name': 'TrickBot', 'c2': '103.15.55.220', 'size': 25000, 'first_seen': '2024-02-07'},
            {'name': 'Dridex', 'c2': '212.47.229.150', 'size': 10000, 'first_seen': '2024-02-14'}
        ]
        
        # Ransomware feeds
        self.feeds['ransomware'] = [
            {'name': 'LockBit', 'version': '3.0', 'first_seen': '2024-01-05', 'victims': 50},
            {'name': 'BlackCat', 'version': '2.0', 'first_seen': '2024-01-17', 'victims': 35},
            {'name': 'Royal', 'version': '1.0', 'first_seen': '2024-01-28', 'victims': 25},
            {'name': 'Play', 'version': '1.5', 'first_seen': '2024-02-09', 'victims': 15},
            {'name': 'BianLian', 'version': '2.5', 'first_seen': '2024-02-13', 'victims': 20}
        ]
        
        print("[+] Feed data generated")
        return self.feeds
    
    def aggregate_feeds(self):
        """Aggregate all feeds into single dataset"""
        all_data = []
        
        for category, items in self.feeds.items():
            for item in items:
                item['category'] = category
                item['timestamp'] = datetime.now().isoformat()
                all_data.append(item)
        
        return all_data
    
    def search_iocs(self, ioc_type, value):
        """Search for IOC in feeds"""
        results = []
        
        if ioc_type == 'ip':
            for botnet in self.feeds['botnet']:
                if botnet['c2'] == value:
                    results.append(botnet)
        
        elif ioc_type == 'name':
            for category in self.feeds:
                for item in self.feeds[category]:
                    if item.get('name', '').lower() == value.lower():
                        results.append(item)
        
        return results
    
    def save_feeds(self, filename='threat_feeds.json'):
        """Save feeds to JSON file"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'feeds': self.feeds
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Feeds saved to {filename}")

def main():
    print("="*60)
    print("📡 THREAT FEED AGGREGATOR - Educational Tool")
    print("="*60)
    
    aggregator = ThreatFeedAggregator()
    
    print("\n📌 Options:")
    print("1. Generate feed data")
    print("2. Save feeds to file")
    print("3. Aggregate all feeds")
    print("4. Search IOCs")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        aggregator.generate_feed_data()
    elif choice == "2":
        aggregator.generate_feed_data()
        aggregator.save_feeds()
    elif choice == "3":
        aggregator.generate_feed_data()
        all_data = aggregator.aggregate_feeds()
        print(f"\n[+] Aggregated {len(all_data)} items")
        for item in all_data[:5]:
            print(f"  • {item.get('name', item.get('target', 'Unknown'))} - {item['category']}")
    elif choice == "4":
        ioc_type = input("Enter IOC type (ip/name): ").strip()
        value = input("Enter value to search: ").strip()
        aggregator.generate_feed_data()
        results = aggregator.search_iocs(ioc_type, value)
        
        if results:
            print(f"\n[+] Found {len(results)} matches:")
            for result in results:
                print(f"  • {result}")
        else:
            print("[!] No matches found")
    else:
        print("[!] Invalid choice")

if __name__ == "__main__":
    main()