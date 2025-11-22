"""
Overview page - Executive dashboard with key metrics
Single page, no scrolling, perfect fit
"""
from dash import html, dcc
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import pandas as pd
import sqlite3
from datetime import datetime

# Colors
COLORS = {
    'white': '#FFFBFF',
    'primary': '#004F60',
    'dark': '#5B4750',
    'accent': '#5FABC5',
    'success': '#C5D94D',
    'warning': '#FCD24A',
    'light': '#D6DBDE',
    'secondary': '#A7CCCE',
    'danger': '#DC3545'
}

def get_stats():
    """Get summary statistics"""
    conn = sqlite3.connect('data/threats.db')
    
    total = pd.read_sql_query('SELECT COUNT(*) as c FROM incidents', conn).iloc[0]['c']
    critical = pd.read_sql_query("SELECT COUNT(*) as c FROM incidents WHERE severity='critical'", conn).iloc[0]['c']
    classified = pd.read_sql_query('SELECT COUNT(DISTINCT incident_id) as c FROM threat_classifications', conn).iloc[0]['c']
    mitre = pd.read_sql_query('SELECT COUNT(DISTINCT technique_id) as c FROM mitre_mappings', conn).iloc[0]['c']
    
    conn.close()
    return {'total': total, 'critical': critical, 'classified': classified, 'mitre': mitre}

def create_timeline_chart():
    """Compact timeline"""
    conn = sqlite3.connect('data/threats.db')
    df = pd.read_sql_query('''
        SELECT DATE(date_discovered) as date, COUNT(*) as count
        FROM incidents WHERE date_discovered IS NOT NULL
        GROUP BY DATE(date_discovered) ORDER BY date
    ''', conn)
    conn.close()
    
    if len(df) == 0:
        return go.Figure()
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['date'], y=df['count'],
        fill='tozeroy',
        line=dict(color=COLORS['primary'], width=3),
        fillcolor=f"rgba(0, 79, 96, 0.1)"
    ))
    
    fig.update_layout(
        template='plotly_white',
        height=200,
        margin=dict(l=40, r=20, t=30, b=40),
        xaxis_title="", yaxis_title="Incidents",
        title=dict(text="Threat Timeline", font=dict(size=14)),
        showlegend=False
    )
    
    return fig

def create_severity_chart():
    """Compact severity breakdown"""
    conn = sqlite3.connect('data/threats.db')
    df = pd.read_sql_query('''
        SELECT severity, COUNT(*) as count FROM incidents 
        WHERE severity IS NOT NULL GROUP BY severity
    ''', conn)
    conn.close()
    
    if len(df) == 0:
        return go.Figure()
    
    colors = {
        'critical': COLORS['danger'],
        'high': COLORS['warning'],
        'medium': COLORS['accent'],
        'low': COLORS['success']
    }
    
    fig = go.Figure(data=[go.Bar(
        x=df['severity'],
        y=df['count'],
        marker_color=[colors.get(s, COLORS['primary']) for s in df['severity']],
        text=df['count'],
        textposition='outside'
    )])
    
    fig.update_layout(
        template='plotly_white',
        height=200,
        margin=dict(l=40, r=20, t=30, b=40),
        xaxis_title="", yaxis_title="Count",
        title=dict(text="Severity Levels", font=dict(size=14)),
        showlegend=False
    )
    
    return fig

def create_threat_types_chart():
    """Compact threat type distribution"""
    conn = sqlite3.connect('data/threats.db')
    df = pd.read_sql_query('''
        SELECT tech_category, COUNT(*) as count FROM threat_classifications
        WHERE tech_category IS NOT NULL GROUP BY tech_category ORDER BY count DESC LIMIT 5
    ''', conn)
    conn.close()
    
    if len(df) == 0:
        return go.Figure()
    
    fig = go.Figure(data=[go.Pie(
        labels=df['tech_category'],
        values=df['count'],
        hole=0.4,
        marker=dict(colors=[COLORS['primary'], COLORS['accent'], COLORS['dark'], 
                           COLORS['warning'], COLORS['success']])
    )])
    
    fig.update_layout(
        template='plotly_white',
        height=200,
        margin=dict(l=20, r=20, t=30, b=20),
        title=dict(text="Top Threat Types", font=dict(size=14)),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5)
    )
    
    return fig

def create_mitre_top3():
    """Top 3 MITRE techniques"""
    conn = sqlite3.connect('data/threats.db')
    df = pd.read_sql_query('''
        SELECT technique_id, technique_name, COUNT(DISTINCT incident_id) as count
        FROM mitre_mappings GROUP BY technique_id, technique_name
        ORDER BY count DESC LIMIT 3
    ''', conn)
    conn.close()
    
    if len(df) == 0:
        return go.Figure()
    
    fig = go.Figure(data=[go.Bar(
        y=[f"{row['technique_id']}: {row['technique_name'][:25]}" for _, row in df.iterrows()],
        x=df['count'],
        orientation='h',
        marker_color=COLORS['dark'],
        text=df['count'],
        textposition='outside'
    )])
    
    fig.update_layout(
        template='plotly_white',
        height=200,
        margin=dict(l=150, r=20, t=30, b=40),
        xaxis_title="Incidents", yaxis_title="",
        title=dict(text="Top 3 MITRE Techniques", font=dict(size=14)),
        yaxis=dict(autorange="reversed"),
        showlegend=False
    )
    
    return fig

# Stats cards
def create_stat_card(title, value, icon, color, subtitle=""):
    return dbc.Card([
        dbc.CardBody([
            html.Div([
                html.Div([
                    html.H2(icon, style={'fontSize': '36px', 'marginBottom': '0'}),
                ], style={'textAlign': 'center', 'marginBottom': '10px'}),
                html.H3(str(value), style={'color': color, 'fontWeight': 'bold', 
                                          'fontSize': '32px', 'marginBottom': '5px', 'textAlign': 'center'}),
                html.P(title, style={'color': '#6B7280', 'fontSize': '14px', 
                                    'marginBottom': '0', 'textAlign': 'center', 'fontWeight': '500'}),
                html.P(subtitle, style={'color': '#9CA3AF', 'fontSize': '11px', 
                                       'marginTop': '5px', 'textAlign': 'center'})
            ])
        ], style={'padding': '20px'})
    ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 
             'borderRadius': '12px', 'height': '100%'})

# Layout - SINGLE PAGE, NO SCROLLING
layout = dbc.Container([
    # Last Updated Timestamp
    html.Div([
        html.Div([
            html.Span("🕐 Last Updated: ", style={'fontWeight': 'bold', 'color': COLORS['dark']}),
            html.Span(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                     style={'color': COLORS['accent']})
        ], style={'textAlign': 'right', 'marginBottom': '10px', 'fontSize': '14px'})
    ], style={'backgroundColor': COLORS['white'], 'padding': '10px', 'borderRadius': '8px',
             'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'marginBottom': '15px', 'marginTop': '20px'}),
    
    # Stats Row
    dbc.Row([
        dbc.Col(create_stat_card("Total Incidents", get_stats()['total'], "📊", 
                                COLORS['primary'], "Collected"), width=3),
        dbc.Col(create_stat_card("Critical Threats", get_stats()['critical'], "🚨", 
                                COLORS['danger'], "High Priority"), width=3),
        dbc.Col(create_stat_card("Classified", get_stats()['classified'], "🧠", 
                                COLORS['success'], "Analyzed"), width=3),
        dbc.Col(create_stat_card("MITRE Techniques", get_stats()['mitre'], "🎯", 
                                COLORS['accent'], "Identified"), width=3),
    ], className="mb-3"),
    
    # Charts Row 1 - Timeline + Severity
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([dcc.Graph(figure=create_timeline_chart(), config={'displayModeBar': False})])
            ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ], width=8),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([dcc.Graph(figure=create_severity_chart(), config={'displayModeBar': False})])
            ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ], width=4),
    ], className="mb-3"),
    
    # Charts Row 2 - Threat Types + MITRE Top 3
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([dcc.Graph(figure=create_threat_types_chart(), config={'displayModeBar': False})])
            ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ], width=4),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([dcc.Graph(figure=create_mitre_top3(), config={'displayModeBar': False})])
            ], style={'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ], width=8),
    ]),
    
], fluid=True, style={'padding': '20px', 'maxWidth': '1400px', 'margin': '0 auto'})