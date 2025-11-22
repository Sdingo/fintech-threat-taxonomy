import sqlite3
import pandas as pd

def view_summary():
    """Display database summary statistics"""
    # FIX: Use relative path from project root
    conn = sqlite3.connect('data/threats.db')  # Changed from ../../data/threats.db
    
    # Total incidents by source
    print("\n📊 INCIDENTS BY SOURCE TYPE")
    print("=" * 60)
    df_sources = pd.read_sql_query('''
        SELECT 
            source_type,
            COUNT(*) as count,
            AVG(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) * 100 as pct_critical
        FROM incidents
        GROUP BY source_type
        ORDER BY count DESC
    ''', conn)
    print(df_sources.to_string(index=False))
    
    # Recent incidents
    print("\n\n📰 MOST RECENT INCIDENTS")
    print("=" * 60)
    df_recent = pd.read_sql_query('''
        SELECT 
            substr(incident_id, 1, 15) as id,
            substr(title, 1, 50) as title,
            severity,
            source_type,
            date(date_discovered) as discovered
        FROM incidents
        ORDER BY date_discovered DESC
        LIMIT 10
    ''', conn)
    print(df_recent.to_string(index=False))
    
    # Severity distribution
    print("\n\n⚠️  SEVERITY DISTRIBUTION")
    print("=" * 60)
    df_severity = pd.read_sql_query('''
        SELECT 
            severity,
            COUNT(*) as count
        FROM incidents
        WHERE severity IS NOT NULL
        GROUP BY severity
        ORDER BY 
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END
    ''', conn)
    print(df_severity.to_string(index=False))
    
    conn.close()
    
    print("\n" + "=" * 60)
    print("💡 Database location: data/threats.db")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    view_summary()