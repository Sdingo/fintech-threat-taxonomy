"""
MITRE ATT&CK Technique Frequency Chart
Shows the most common attack techniques in FinTech
"""
import sqlite3
import plotly.graph_objects as go
import pandas as pd

def create_technique_chart():
    """Create bar chart of top MITRE techniques"""
    conn = sqlite3.connect('data/threats.db')
    
    df = pd.read_sql_query('''
        SELECT 
            technique_id,
            technique_name,
            tactic_name,
            COUNT(DISTINCT incident_id) as incidents,
            AVG(confidence) as avg_confidence
        FROM mitre_mappings
        GROUP BY technique_id, technique_name, tactic_name
        ORDER BY incidents DESC
        LIMIT 15
    ''', conn)
    
    conn.close()
    
    if len(df) == 0:
        print("⚠️  No MITRE mappings found!")
        return
    
    # Create color map based on tactic
    tactic_colors = {
        'Initial Access': '#FF6B6B',
        'Execution': '#4ECDC4',
        'Persistence': '#45B7D1',
        'Privilege Escalation': '#96CEB4',
        'Defense Evasion': '#FFEAA7',
        'Credential Access': '#DFE6E9',
        'Discovery': '#74B9FF',
        'Lateral Movement': '#A29BFE',
        'Collection': '#FD79A8',
        'Exfiltration': '#FDCB6E',
        'Command and Control': '#6C5CE7',
        'Impact': '#E17055'
    }
    
    colors = [tactic_colors.get(tactic, '#95A5A6') for tactic in df['tactic_name']]
    
    # Create figure
    fig = go.Figure(data=[
        go.Bar(
            x=df['incidents'],
            y=[f"{row['technique_id']}: {row['technique_name'][:30]}" 
               for _, row in df.iterrows()],
            orientation='h',
            marker=dict(
                color=colors,
                line=dict(color='rgba(0,0,0,0.3)', width=1)
            ),
            text=df['incidents'],
            textposition='outside',
            hovertemplate='<b>%{y}</b><br>' +
                         'Incidents: %{x}<br>' +
                         'Tactic: %{customdata[0]}<br>' +
                         'Confidence: %{customdata[1]:.2f}<extra></extra>',
            customdata=df[['tactic_name', 'avg_confidence']].values
        )
    ])
    
    fig.update_layout(
        title={
            'text': '🎯 Top 15 MITRE ATT&CK Techniques in FinTech Threats',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20}
        },
        xaxis_title="Number of Incidents",
        yaxis_title="",
        height=700,
        width=1200,
        font=dict(size=11),
        showlegend=False,
        yaxis=dict(autorange="reversed")
    )
    
    # Save
    output_file = 'reports/technique_frequency.html'
    fig.write_html(output_file)
    
    print(f"\n✅ Technique frequency chart saved: {output_file}")
    
    return fig

if __name__ == "__main__":
    print("=" * 70)
    print("📊 Generating MITRE Technique Frequency Chart...")
    print("=" * 70)
    
    create_technique_chart()
    
    print("\n✅ Chart complete!")