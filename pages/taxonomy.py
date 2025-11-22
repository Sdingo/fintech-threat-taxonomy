"""
Multi-Dimensional Taxonomy Page
"""
from dash import html, dcc
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import pandas as pd
import sqlite3

COLORS = {
    'primary': '#004F60', 
    'secondary': '#A7CCCE', 
    'accent': '#5FABC5',
    'dark': '#5B4750',
    'success': '#C5D94D'
}

def get_taxonomy_data():
    conn = sqlite3.connect('data/threats.db')
    
    tech = pd.read_sql_query('SELECT tech_category, COUNT(*) as c FROM threat_classifications WHERE tech_category IS NOT NULL GROUP BY tech_category', conn)
    human = pd.read_sql_query('SELECT human_category, COUNT(*) as c FROM threat_classifications WHERE human_category IS NOT NULL GROUP BY human_category', conn)
    proc = pd.read_sql_query('SELECT procedural_category, COUNT(*) as c FROM threat_classifications WHERE procedural_category IS NOT NULL GROUP BY procedural_category', conn)
    
    conn.close()
    return tech, human, proc

def create_dimension_chart(df, title, color):
    if len(df) == 0:
        return go.Figure()
    
    fig = go.Figure(data=[go.Bar(
        x=df.iloc[:, 0],
        y=df.iloc[:, 1],
        marker_color=color,
        text=df.iloc[:, 1],
        textposition='outside'
    )])
    
    fig.update_layout(
        title=title,
        template='plotly_white',
        height=300,
        showlegend=False,
        xaxis_title="", yaxis_title="Count"
    )
    
    return fig

tech, human, proc = get_taxonomy_data()

layout = dbc.Container([
    html.H2("🧠 Multi-Dimensional Threat Taxonomy", style={'color': COLORS['primary'], 'marginTop': '20px', 'marginBottom': '20px'}),
    
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("📱 Technology Dimension", style={'color': COLORS['primary']}),
                    dcc.Graph(figure=create_dimension_chart(tech, "Technology Threats", COLORS['primary']), 
                             config={'displayModeBar': False})
                ])
            ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ], width=12),
    ], className="mb-3"),
    
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("👤 Human Dimension", style={'color': COLORS['dark']}),
                    dcc.Graph(figure=create_dimension_chart(human, "Human-Originated Threats", COLORS['dark']), 
                             config={'displayModeBar': False})
                ])
            ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ], width=6),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("⚙️ Procedural Dimension", style={'color': COLORS['accent']}),
                    dcc.Graph(figure=create_dimension_chart(proc, "Procedural Threats", COLORS['accent']), 
                             config={'displayModeBar': False})
                ])
            ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ], width=6),
    ]),
    
], fluid=True, style={'padding': '20px', 'maxWidth': '1400px', 'margin': '0 auto'})