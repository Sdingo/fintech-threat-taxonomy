import requests
import sqlite3
from datetime import datetime, timedelta
import time
import hashlib

class CVECollector:
    """
    Collects CVE (Common Vulnerabilities and Exposures) data
    for FinTech-related software and systems
    """
    
    # NVD (National Vulnerability Database) API
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # FinTech-related software/vendors to monitor
    FINTECH_VENDORS = [
        'stripe', 'square', 'paypal', 'plaid', 'coinbase', 'binance',
        'revolut', 'n26', 'chime', 'robinhood', 'wealthfront', 'betterment',
        'oracle financial', 'fis', 'fiserv', 'jack henry', 'temenos',
        'finastra', 'salesforce financial', 'sap financial'
    ]
    
    FINTECH_KEYWORDS = [
        'payment', 'banking', 'financial', 'transaction', 'wallet',
        'cryptocurrency', 'blockchain', 'lending', 'credit', 'atm',
        'pos terminal', 'swift', 'trading platform', 'forex'
    ]
    
    def __init__(self, db_path='data/threats.db', api_key=None):
        """
        Initialize CVE collector
        
        Args:
            db_path: Path to SQLite database
            api_key: NVD API key (optional, increases rate limit)
        """
        self.db_path = db_path
        self.api_key = api_key
        self.headers = {}
        
        if api_key:
            self.headers['apiKey'] = api_key
    
    def collect_recent_cves(self, days_back=30):
        """
        Collect recent CVEs related to FinTech
        
        Args:
            days_back: Number of days to look back
        """
        print(f"\n🔍 Searching NVD for FinTech CVEs (last {days_back} days)...")
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        # Format dates for NVD API (ISO 8601)
        pub_start = start_date.strftime('%Y-%m-%dT00:00:00.000')
        pub_end = end_date.strftime('%Y-%m-%dT23:59:59.999')
        
        all_cves = []
        
        # Search by keywords
        for keyword in self.FINTECH_KEYWORDS[:3]:  # Limit to avoid rate limiting
            print(f"  🔎 Searching for '{keyword}'...")
            
            params = {
                'pubStartDate': pub_start,
                'pubEndDate': pub_end,
                'keywordSearch': keyword,
                'resultsPerPage': 20
            }
            
            try:
                response = requests.get(
                    self.NVD_API_BASE,
                    params=params,
                    headers=self.headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        cve_data = self._parse_cve(vuln)
                        if cve_data:
                            all_cves.append(cve_data)
                    
                    print(f"    ✅ Found {len(vulnerabilities)} CVEs")
                
                elif response.status_code == 403:
                    print(f"    ⚠️  Rate limited. Waiting 6 seconds...")
                    time.sleep(6)
                    continue
                
                else:
                    print(f"    ❌ Error {response.status_code}")
                
                # Respect rate limits (5 requests per 30 seconds without API key)
                time.sleep(6)
                
            except Exception as e:
                print(f"    ❌ Error: {str(e)}")
                continue
        
        print(f"\n🎯 Total FinTech CVEs collected: {len(all_cves)}")
        return all_cves
    
    def _parse_cve(self, vulnerability):
        """Parse CVE data from NVD response"""
        try:
            cve = vulnerability.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Get description
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS score (severity)
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            severity = 'unknown'
            
            # Try CVSS v3.1 first
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'unknown').lower()
            
            # Fallback to CVSS v2
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = self._cvss_v2_to_severity(cvss_score)
            
            # Get publication date
            published = cve.get('published', '')
            pub_date = datetime.fromisoformat(published.replace('Z', '+00:00')) if published else datetime.now()
            
            # Get references
            references = cve.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references[:3]]  # First 3 refs
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published': pub_date,
                'references': ref_urls
            }
            
        except Exception as e:
            print(f"    ⚠️  Error parsing CVE: {str(e)}")
            return None
    
    def save_to_database(self, cves):
        """Save CVEs to database as incidents"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        saved_count = 0
        duplicate_count = 0
        
        for cve in cves:
            # Generate incident ID from CVE ID
            incident_id = f"cve_{cve['cve_id'].lower().replace('-', '_')}"
            
            # Map CVSS severity to our severity scale
            severity_map = {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low',
                'unknown': 'medium'
            }
            severity = severity_map.get(cve['severity'], 'medium')
            
            # Create title
            title = f"{cve['cve_id']} - FinTech Vulnerability ({cve['severity'].upper()})"
            
            # Build source URL
            source_url = f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}"
            if cve['references']:
                source_url = cve['references'][0]
            
            try:
                cursor.execute('''
                INSERT INTO incidents (
                    incident_id, title, description, date_discovered,
                    source_url, source_type, severity, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident_id,
                    title,
                    cve['description'][:500],  # Truncate long descriptions
                    cve['published'],
                    source_url,
                    'cve',
                    severity,
                    'active',
                    datetime.now()
                ))
                saved_count += 1
                
            except sqlite3.IntegrityError:
                duplicate_count += 1
                continue
        
        conn.commit()
        conn.close()
        
        print(f"\n💾 Saved {saved_count} new CVEs")
        print(f"⏭️  Skipped {duplicate_count} duplicates")
        
        return saved_count
    
    def _cvss_v2_to_severity(self, score):
        """Convert CVSS v2 score to severity rating"""
        if score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        else:
            return 'low'

# Test the collector
if __name__ == "__main__":
    collector = CVECollector()
    
    print("🚀 Starting CVE collection...")
    print("⚠️  Note: NVD API has rate limits (5 requests/30 sec)")
    print("   This may take 1-2 minutes...\n")
    
    cves = collector.collect_recent_cves(days_back=30)
    
    if cves:
        collector.save_to_database(cves)
        print("\n✅ CVE collection complete!")
    else:
        print("\n⚠️  No CVEs found")