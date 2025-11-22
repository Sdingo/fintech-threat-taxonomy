"""
MITRE ATT&CK Heatmap Visualization
Shows which techniques are most common in FinTech threats
"""
import sqlite3
import plotly.graph_objects as go
import pandas as pd

def create_mitre_heatmap():
    """Create interactive MITRE ATT&CK heatmap"""
    conn = sqlite3.connect('data/threats.db')
    
    # Get technique mappings with tactics
    df = pd.read_sql_query('''
        SELECT 
            tactic_name,
            technique_id,
            technique_name,
            COUNT(*) as count,
            AVG(confidence) as avg_confidence
        FROM mitre_mappings
        GROUP BY tactic_name, technique_id, technique_name
        ORDER BY count DESC
    ''', conn)
    
    conn.close()
    
    if len(df) == 0:
        print("⚠️  No MITRE mappings found. Run mitre_mapper.py first!")
        return
    
    # Prepare data for heatmap
    tactics = df['tactic_name'].unique()
    
    # Create matrix data
    heatmap_data = []
    hover_texts = []
    
    for tactic in tactics:
        tactic_data = df[df['tactic_name'] == tactic]
        
        # Get top 5 techniques per tactic
        top_techniques = tactic_data.nlargest(5, 'count')
        
        values = []
        hovers = []
        
        for _, row in top_techniques.iterrows():
            values.append(row['count'])
            hovers.append(
                f"<b>{row['technique_id']}: {row['technique_name']}</b><br>"
                f"Tactic: {row['tactic_name']}<br>"
                f"Incidents: {row['count']}<br>"
                f"Avg Confidence: {row['avg_confidence']:.2f}"
            )
        
        heatmap_data.append(values)
        hover_texts.append(hovers)
    
    # Create figure
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data,
        x=[f"Top {i+1}" for i in range(5)],
        y=list(tactics),
        colorscale='Reds',
        text=hover_texts,
        hovertemplate='%{text}<extra></extra>',
        colorbar=dict(title="Incidents")
    ))
    
    fig.update_layout(
        title={
            'text': '🎯 MITRE ATT&CK Heatmap - FinTech Threat Landscape',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20}
        },
        xaxis_title="Top Techniques per Tactic",
        yaxis_title="MITRE ATT&CK Tactics",
        height=600,
        width=1000,
        font=dict(size=12)
    )
    
    # Save to HTML
    output_file = 'reports/mitre_heatmap.html'
    fig.write_html(output_file)
    
    print(f"\n✅ MITRE ATT&CK heatmap saved: {output_file}")
    print(f"   Open in browser to view interactive visualization")
    
    return fig

if __name__ == "__main__":
    print("=" * 70)
    print("🎨 Generating MITRE ATT&CK Heatmap...")
    print("=" * 70)
    
    create_mitre_heatmap()
    
    print("\n✅ Visualization complete!")