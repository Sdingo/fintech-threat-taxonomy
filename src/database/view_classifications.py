import sqlite3
import pandas as pd

def view_classifications():
    """Display classification results"""
    conn = sqlite3.connect('data/threats.db')
    
    print("\n" + "=" * 70)
    print("🧠 THREAT CLASSIFICATION ANALYSIS")
    print("=" * 70)
    
    # Technology dimension
    print("\n📱 DIMENSION 1: TECHNOLOGY-BASED THREATS")
    print("-" * 70)
    df_tech = pd.read_sql_query('''
        SELECT 
            tech_category,
            tech_subcategory,
            COUNT(*) as count
        FROM threat_classifications
        WHERE tech_category IS NOT NULL
        GROUP BY tech_category, tech_subcategory
        ORDER BY count DESC
        LIMIT 10
    ''', conn)
    print(df_tech.to_string(index=False))
    
    # Human dimension
    print("\n\n👤 DIMENSION 2: HUMAN-ORIGINATED THREATS")
    print("-" * 70)
    df_human = pd.read_sql_query('''
        SELECT 
            human_category,
            human_subcategory,
            COUNT(*) as count
        FROM threat_classifications
        WHERE human_category IS NOT NULL
        GROUP BY human_category, human_subcategory
        ORDER BY count DESC
        LIMIT 10
    ''', conn)
    print(df_human.to_string(index=False))
    
    # Procedural dimension
    print("\n\n⚙️  DIMENSION 3: PROCEDURAL THREATS")
    print("-" * 70)
    df_proc = pd.read_sql_query('''
        SELECT 
            procedural_category,
            procedural_subcategory,
            COUNT(*) as count
        FROM threat_classifications
        WHERE procedural_category IS NOT NULL
        GROUP BY procedural_category, procedural_subcategory
        ORDER BY count DESC
        LIMIT 10
    ''', conn)
    print(df_proc.to_string(index=False))
    
    # Sample classified incidents
    print("\n\n📋 SAMPLE CLASSIFIED INCIDENTS")
    print("-" * 70)
    df_sample = pd.read_sql_query('''
        SELECT 
            substr(i.title, 1, 40) as title,
            tc.tech_category as tech,
            tc.human_category as human,
            tc.procedural_category as proc,
            ROUND(tc.confidence_score, 2) as confidence
        FROM incidents i
        JOIN threat_classifications tc ON i.incident_id = tc.incident_id
        ORDER BY tc.confidence_score DESC
        LIMIT 10
    ''', conn)
    print(df_sample.to_string(index=False))
    
    conn.close()
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    view_classifications()