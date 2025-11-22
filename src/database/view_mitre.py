import sqlite3
import pandas as pd

def view_mitre_analysis():
    """Display MITRE ATT&CK mapping analysis"""
    conn = sqlite3.connect('data/threats.db')
    
    print("\n" + "=" * 80)
    print("🎯 MITRE ATT&CK MAPPING ANALYSIS - FINTECH THREATS")
    print("=" * 80)
    
    # Top tactics
    print("\n📊 TOP MITRE ATT&CK TACTICS (The 'Why' of Attacks)")
    print("-" * 80)
    df_tactics = pd.read_sql_query('''
        SELECT 
            tactic_id,
            tactic_name,
            COUNT(DISTINCT incident_id) as incidents,
            COUNT(*) as total_mappings,
            ROUND(AVG(confidence), 2) as avg_confidence
        FROM mitre_mappings
        GROUP BY tactic_id, tactic_name
        ORDER BY incidents DESC
    ''', conn)
    print(df_tactics.to_string(index=False))
    
    # Top techniques
    print("\n\n🔧 TOP MITRE ATT&CK TECHNIQUES (The 'How' of Attacks)")
    print("-" * 80)
    df_techniques = pd.read_sql_query('''
        SELECT 
            technique_id,
            technique_name,
            tactic_name,
            COUNT(DISTINCT incident_id) as incidents,
            ROUND(AVG(confidence), 2) as confidence
        FROM mitre_mappings
        GROUP BY technique_id, technique_name, tactic_name
        ORDER BY incidents DESC, confidence DESC
        LIMIT 10
    ''', conn)
    print(df_techniques.to_string(index=False))
    
    # Sample incidents with MITRE mappings
    print("\n\n📋 SAMPLE INCIDENTS WITH MITRE ATT&CK MAPPINGS")
    print("-" * 80)
    df_samples = pd.read_sql_query('''
        SELECT 
            substr(i.title, 1, 45) as incident,
            GROUP_CONCAT(DISTINCT m.technique_id) as techniques,
            COUNT(DISTINCT m.technique_id) as tech_count
        FROM incidents i
        JOIN mitre_mappings m ON i.incident_id = m.incident_id
        GROUP BY i.incident_id, i.title
        ORDER BY tech_count DESC
        LIMIT 10
    ''', conn)
    print(df_samples.to_string(index=False))
    
    # Coverage statistics
    print("\n\n📈 COVERAGE STATISTICS")
    print("-" * 80)
    
    cursor = conn.cursor()
    
    # Total incidents
    cursor.execute('SELECT COUNT(*) FROM incidents')
    total_incidents = cursor.fetchone()[0]
    
    # Mapped incidents
    cursor.execute('SELECT COUNT(DISTINCT incident_id) FROM mitre_mappings')
    mapped_incidents = cursor.fetchone()[0]
    
    # Unique techniques
    cursor.execute('SELECT COUNT(DISTINCT technique_id) FROM mitre_mappings')
    unique_techniques = cursor.fetchone()[0]
    
    # Unique tactics
    cursor.execute('SELECT COUNT(DISTINCT tactic_id) FROM mitre_mappings')
    unique_tactics = cursor.fetchone()[0]
    
    coverage_pct = (mapped_incidents / total_incidents * 100) if total_incidents > 0 else 0
    
    print(f"Total Incidents:           {total_incidents}")
    print(f"Mapped to MITRE:           {mapped_incidents}")
    print(f"Coverage:                  {coverage_pct:.1f}%")
    print(f"Unique Techniques Used:    {unique_techniques} / 202 total")
    print(f"Unique Tactics Used:       {unique_tactics} / 12 total")
    
    conn.close()
    
    print("\n" + "=" * 80)
    print("💡 Import 'reports/attack_navigator.json' into MITRE ATT&CK Navigator")
    print("   URL: https://mitre-attack.github.io/attack-navigator/")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    view_mitre_analysis()