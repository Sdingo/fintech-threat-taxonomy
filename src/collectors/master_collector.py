"""
Master collector - runs all data collection modules
"""
from rss_collector import RSSCollector
from cve_collector import CVECollector
from otx_collector import OTXCollector
from datetime import datetime

def run_all_collectors(otx_api_key=None):
    """Run all data collectors"""
    print("\n" + "=" * 60)
    print(f"🚀 MASTER COLLECTOR - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    total_collected = 0
    
    # 1. RSS News Feeds
    print("\n📰 STEP 1: Collecting from RSS feeds...")
    print("-" * 60)
    rss = RSSCollector()
    articles = rss.collect_all_feeds(days_back=7)
    saved = rss.save_to_database(articles)
    total_collected += saved
    
    # 2. CVE Database
    print("\n🔍 STEP 2: Collecting CVE vulnerabilities...")
    print("-" * 60)
    cve = CVECollector()
    cves = cve.collect_recent_cves(days_back=30)
    saved = cve.save_to_database(cves)
    total_collected += saved
    
    # 3. OTX Threat Intelligence (if API key provided)
    if otx_api_key:
        print("\n🌐 STEP 3: Collecting from AlienVault OTX...")
        print("-" * 60)
        otx = OTXCollector(api_key=otx_api_key)
        pulses = otx.collect_recent_pulses(days_back=7)
        saved = otx.save_to_database(pulses)
        total_collected += saved
    else:
        print("\n⏭️  STEP 3: Skipping OTX (no API key)")
    
    # Summary
    print("\n" + "=" * 60)
    print(f"✅ COLLECTION COMPLETE")
    print("=" * 60)
    print(f"Total new incidents collected: {total_collected}")
    print(f"Run time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n💡 Next: Run classification engine to categorize threats")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    # Run all collectors
    otx_key = None  # Add your OTX API key here if you have one
    run_all_collectors(otx_api_key=otx_key)