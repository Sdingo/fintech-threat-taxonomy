"""
Report generation module
Exports data as CSV, PDF reports
"""
import pandas as pd
import sqlite3
from datetime import datetime
import json
import os

class ReportGenerator:
    """Generate reports from threat data"""
    
    def __init__(self, db_path='data/threats.db'):
        self.db_path = db_path
    
    def export_incidents_csv(self, output_file='reports/incidents_export.csv'):
        """Export all incidents to CSV"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT 
                i.incident_id,
                i.title,
                i.description,
                i.date_discovered,
                i.severity,
                i.source_type,
                i.source_url,
                tc.tech_category,
                tc.human_category,
                tc.procedural_category
            FROM incidents i
            LEFT JOIN threat_classifications tc ON i.incident_id = tc.incident_id
            ORDER BY i.date_discovered DESC
        ''', conn)
        
        conn.close()
        
        os.makedirs('reports', exist_ok=True)
        df.to_csv(output_file, index=False)
        
        print(f"✅ Exported {len(df)} incidents to {output_file}")
        return output_file
    
    def export_mitre_mappings_csv(self, output_file='reports/mitre_mappings.csv'):
        """Export MITRE ATT&CK mappings to CSV"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT 
                m.incident_id,
                i.title,
                m.tactic_id,
                m.tactic_name,
                m.technique_id,
                m.technique_name,
                m.confidence,
                i.severity
            FROM mitre_mappings m
            JOIN incidents i ON m.incident_id = i.incident_id
            ORDER BY m.technique_id
        ''', conn)
        
        conn.close()
        
        df.to_csv(output_file, index=False)
        
        print(f"✅ Exported {len(df)} MITRE mappings to {output_file}")
        return output_file
    
    def generate_executive_summary(self, output_file='reports/executive_summary.txt'):
        """Generate text-based executive summary"""
        conn = sqlite3.connect(self.db_path)
        
        # Get statistics
        total_incidents = pd.read_sql_query('SELECT COUNT(*) as c FROM incidents', conn).iloc[0]['c']
        critical = pd.read_sql_query("SELECT COUNT(*) as c FROM incidents WHERE severity='critical'", conn).iloc[0]['c']
        
        # Top threats
        top_tech = pd.read_sql_query('''
            SELECT tech_category, COUNT(*) as c FROM threat_classifications 
            WHERE tech_category IS NOT NULL GROUP BY tech_category 
            ORDER BY c DESC LIMIT 3
        ''', conn)
        
        # Top MITRE
        top_mitre = pd.read_sql_query('''
            SELECT technique_id, technique_name, COUNT(*) as c FROM mitre_mappings
            GROUP BY technique_id, technique_name ORDER BY c DESC LIMIT 5
        ''', conn)
        
        conn.close()
        
        # Build report
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║          FINTECH CYBER THREAT INTELLIGENCE REPORT                ║
║                 Executive Summary                                 ║
╚══════════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KEY METRICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Incidents Tracked:        {total_incidents}
Critical Severity Threats:      {critical}
Threat Coverage:                Multi-dimensional (Tech, Human, Procedural)
MITRE ATT&CK Integration:       ✓ Active

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOP THREAT CATEGORIES (Technology Dimension)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        for _, row in top_tech.iterrows():
            report += f"  • {row['tech_category'].upper():<20} {row['c']} incidents\n"
        
        report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOP 5 MITRE ATT&CK TECHNIQUES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        for _, row in top_mitre.iterrows():
            report += f"  {row['technique_id']}: {row['technique_name']:<40} ({row['c']} incidents)\n"
        
        report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECOMMENDATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Focus defenses on top MITRE techniques identified above
2. Implement multi-layered security addressing all 3 dimensions
3. Regular monitoring of threat intelligence feeds
4. Continuous MITRE ATT&CK framework mapping
5. Quarterly review of taxonomy classifications

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DATA SOURCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- RSS Feeds: 6 cybersecurity news sources
- NVD CVE Database: Real-time vulnerability tracking
- MITRE ATT&CK Framework: Technique mapping
- Manual Imports: Breach notifications, reports

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Report generated by FinTech Cyber Threat Taxonomy Dashboard
Built by Phiwokuhle Sdingo Kunene: FinTech + Cybersecurity
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"✅ Executive summary saved to {output_file}")
        return output_file
    
    def export_all(self):
        """Export all reports at once"""
        print("\n" + "=" * 70)
        print("📊 GENERATING ALL REPORTS")
        print("=" * 70 + "\n")
        
        self.export_incidents_csv()
        self.export_mitre_mappings_csv()
        self.generate_executive_summary()
        
        print("\n✅ All reports generated in reports/ folder")
        print("=" * 70 + "\n")

if __name__ == "__main__":
    generator = ReportGenerator()
    generator.export_all()