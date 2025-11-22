import requests
import sqlite3
from datetime import datetime, timedelta
import time

class OTXCollector:
    """
    Collects threat intelligence from AlienVault OTX
    (Open Threat Exchange)
    """
    
    OTX_API_BASE = "https://otx.alienvault.com/api/v1"
    
    # FinTech-related threat tags
    FINTECH_TAGS = [
        'banking', 'financial', 'fintech', 'payment', 'cryptocurrency',
        'ransomware', 'apt', 'targeted-attack'
    ]
    
    def __init__(self, db_path='data/threats.db', api_key=None):
        """
        Initialize OTX collector
        
        Args:
            db_path: Path to SQLite database
            api_key: OTX API key (optional, but recommended)
                     Get free key at: https://otx.alienvault.com/
        """
        self.db_path = db_path
        self.api_key = api_key
        self.headers = {
            'X-OTX-API-KEY': api_key if api_key else ''
        }
    
    def collect_recent_pulses(self, days_back=7):
        """
        Collect recent threat intelligence pulses
        
        Args:
            days_back: Number of days to look back
        """
        print(f"\n🌐 Fetching threat intelligence from OTX...")
        
        if not self.api_key:
            print("⚠️  No API key provided. Using public endpoint (limited data)")
        
        all_pulses = []
        
        try:
            # Get recent pulses
            modified_since = (datetime.now() - timedelta(days=days_back)).isoformat()
            
            params = {
                'modified_since': modified_since,
                'limit': 50
            }
            
            response = requests.get(
                f"{self.OTX_API_BASE}/pulses/subscribed",
                headers=self.headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])
                
                print(f"  📊 Retrieved {len(pulses)} pulses")
                
                for pulse in pulses:
                    if self._is_fintech_related(pulse):
                        pulse_data = self._parse_pulse(pulse)
                        if pulse_data:
                            all_pulses.append(pulse_data)
                
                print(f"  ✅ Found {len(all_pulses)} FinTech-related threats")
                
            elif response.status_code == 403:
                print("  ❌ Invalid or missing API key")
                print("     Get a free key at: https://otx.alienvault.com/api")
                return []
            
            else:
                print(f"  ❌ Error {response.status_code}: {response.text}")
                return []
            
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            return []
        
        return all_pulses
    
    def _is_fintech_related(self, pulse):
        """Check if pulse is related to FinTech"""
        tags = pulse.get('tags', [])
        name = pulse.get('name', '').lower()
        description = pulse.get('description', '').lower()
        
        # Check tags
        for tag in tags:
            if tag.lower() in self.FINTECH_TAGS:
                return True
        
        # Check name and description
        fintech_keywords = [
            'bank', 'financial', 'payment', 'crypto', 'fintech',
            'transaction', 'atm', 'pos', 'swift'
        ]
        
        content = f"{name} {description}"
        return any(keyword in content for keyword in fintech_keywords)
    
    def _parse_pulse(self, pulse):
        """Parse OTX pulse data"""
        try:
            return {
                'id': pulse.get('id', ''),
                'name': pulse.get('name', ''),
                'description': pulse.get('description', ''),
                'created': pulse.get('created', ''),
                'modified': pulse.get('modified', ''),
                'tags': pulse.get('tags', []),
                'references': pulse.get('references', []),
                'tlp': pulse.get('TLP', 'white'),
                'adversary': pulse.get('adversary', ''),
                'targeted_countries': pulse.get('targeted_countries', []),
                'industries': pulse.get('industries', []),
                'attack_ids': pulse.get('attack_ids', []),  # MITRE ATT&CK IDs
                'indicators': len(pulse.get('indicators', []))
            }
        except Exception as e:
            print(f"    ⚠️  Error parsing pulse: {str(e)}")
            return None
    
    def save_to_database(self, pulses):
        """Save OTX pulses to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        saved_count = 0
        duplicate_count = 0
        
        for pulse in pulses:
            incident_id = f"otx_{pulse['id']}"
            
            # Parse date
            try:
                date_discovered = datetime.fromisoformat(
                    pulse['created'].replace('Z', '+00:00')
                )
            except:
                date_discovered = datetime.now()
            
            # Determine severity based on TLP and indicators
            severity = 'medium'
            if pulse['tlp'] == 'red':
                severity = 'critical'
            elif pulse['tlp'] == 'amber':
                severity = 'high'
            elif pulse['indicators'] > 50:
                severity = 'high'
            
            # Build source URL
            source_url = f"https://otx.alienvault.com/pulse/{pulse['id']}"
            
            try:
                cursor.execute('''
                INSERT INTO incidents (
                    incident_id, title, description, date_discovered,
                    source_url, source_type, severity, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident_id,
                    pulse['name'],
                    pulse['description'][:500],
                    date_discovered,
                    source_url,
                    'threat_feed',
                    severity,
                    'active',
                    datetime.now()
                ))
                
                # If pulse has MITRE ATT&CK IDs, save them
                if pulse['attack_ids']:
                    for attack_id in pulse['attack_ids']:
                        self._save_mitre_mapping(cursor, incident_id, attack_id)
                
                saved_count += 1
                
            except sqlite3.IntegrityError:
                duplicate_count += 1
                continue
        
        conn.commit()
        conn.close()
        
        print(f"\n💾 Saved {saved_count} new threat intel pulses")
        print(f"⏭️  Skipped {duplicate_count} duplicates")
        
        return saved_count
    
    def _save_mitre_mapping(self, cursor, incident_id, attack_id):
        """Save MITRE ATT&CK mapping"""
        try:
            # Parse technique ID (format: T1078 or T1078.001)
            parts = attack_id['id'].split('.')
            technique_id = parts[0]
            sub_technique_id = attack_id['id'] if len(parts) > 1 else None
            
            cursor.execute('''
            INSERT INTO mitre_mappings (
                incident_id, technique_id, technique_name,
                sub_technique_id, confidence, mapping_source
            ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                incident_id,
                technique_id,
                attack_id.get('name', ''),
                sub_technique_id,
                0.8,  # High confidence from OTX
                'otx_api'
            ))
        except:
            pass  # Skip if mapping already exists

# Test the collector
if __name__ == "__main__":
    print("=" * 60)
    print("AlienVault OTX Collector")
    print("=" * 60)
    print("\n⚠️  IMPORTANT: This collector works best with an API key")
    print("   Get a FREE API key at: https://otx.alienvault.com/api")
    print("   (Takes 1 minute to sign up)\n")
    
    api_key = input("Enter your OTX API key (or press Enter to skip): ").strip()
    
    if not api_key:
        print("\n⚠️  Running without API key (limited data)...")
        collector = OTXCollector()
    else:
        collector = OTXCollector(api_key=api_key)
    
    print("\n🚀 Starting OTX collection...")
    pulses = collector.collect_recent_pulses(days_back=7)
    
    if pulses:
        collector.save_to_database(pulses)
        print("\n✅ OTX collection complete!")
    else:
        print("\n⚠️  No pulses found (may need API key)")