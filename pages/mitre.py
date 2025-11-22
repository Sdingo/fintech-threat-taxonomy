"""
MITRE ATT&CK Analysis Page
"""
from dash import html, dcc
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import pandas as pd
import sqlite3

COLORS = {
    'white': '#FFFBFF', 'primary': '#004F60', 'dark': '#5B4750', 
    'accent': '#5FABC5', 'success': '#C5D94D', 'warning': '#FCD24A',
    'light': '#D6DBDE', 'secondary': '#A7CCCE'
}

def create_mitre_heatmap():
    """MITRE ATT&CK heatmap"""
    conn = sqlite3.connect('data/threats.db')
    df = pd.read_sql_query('''
        SELECT tactic_name, technique_id, technique_name, COUNT(*) as count
        FROM mitre_mappings GROUP BY tactic_name, technique_id, technique_name
        ORDER BY count DESC LIMIT 20
    ''', conn)
    conn.close()
    
    if len(df) == 0:
        return go.Figure()
    
    fig = go.Figure(data=go.Bar(
        y=[f"{row['technique_id']}: {row['technique_name'][:30]}" for _, row in df.iterrows()],
        x=df['count'],
        orientation='h',
        marker=dict(color=df['count'], colorscale='Viridis', showscale=True),
        text=df['count'],
        textposition='outside'
    ))
    
    fig.update_layout(
        title="Top 20 MITRE ATT&CK Techniques",
        template='plotly_white',
        height=600,
        margin=dict(l=250, r=50, t=50, b=50),
        yaxis=dict(autorange="reversed"),
        xaxis_title="Number of Incidents"
    )
    
    return fig

layout = dbc.Container([
    html.H2("🎯 MITRE ATT&CK Analysis", style={'color': COLORS['primary'], 'marginTop': '20px', 'marginBottom': '20px'}),
    dbc.Card([
        dbc.CardBody([
            dcc.Graph(figure=create_mitre_heatmap(), config={'displayModeBar': True})
        ])
    ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
], fluid=True, style={'padding': '20px', 'maxWidth': '1400px', 'margin': '0 auto'})