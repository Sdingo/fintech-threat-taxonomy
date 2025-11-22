"""
Advanced Analytics Page with Export Functions
"""
from dash import html, callback, Input, Output
import dash_bootstrap_components as dbc
import pandas as pd
import sqlite3
from datetime import datetime

COLORS = {'primary': '#004F60', 'accent': '#5FABC5', 'success': '#C5D94D', 'warning': '#FCD24A'}

def get_export_stats():
    """Get stats for export section"""
    conn = sqlite3.connect('data/threats.db')
    incidents = pd.read_sql_query('SELECT COUNT(*) as c FROM incidents', conn).iloc[0]['c']
    mappings = pd.read_sql_query('SELECT COUNT(*) as c FROM mitre_mappings', conn).iloc[0]['c']
    conn.close()
    return incidents, mappings

incidents, mappings = get_export_stats()

layout = dbc.Container([
    html.H2("📈 Analytics & Export Tools", style={'color': COLORS['primary'], 'marginTop': '20px', 'marginBottom': '30px'}),
    
    # Export Section
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("📊 Data Export", style={'color': COLORS['primary'], 'marginBottom': '20px'}),
                    html.P(f"Export your threat intelligence data for further analysis.", 
                          style={'color': '#6B7280', 'marginBottom': '20px'}),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.H5("📄 Incidents CSV", className="text-center mb-3"),
                                    html.P(f"{incidents} incidents", className="text-center text-muted mb-3"),
                                    dbc.Button("Download CSV", color="primary", className="w-100",
                                             href="/download/incidents", external_link=True)
                                ])
                            ], style={'border': f"2px solid {COLORS['primary']}"})
                        ], width=4),
                        
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.H5("🎯 MITRE Mappings", className="text-center mb-3"),
                                    html.P(f"{mappings} mappings", className="text-center text-muted mb-3"),
                                    dbc.Button("Download CSV", style={'backgroundColor': COLORS['accent'], 'border': 'none'}, 
                                             className="w-100", href="/download/mitre", external_link=True)
                                ])
                            ], style={'border': f"2px solid {COLORS['accent']}"})
                        ], width=4),
                        
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.H5("📋 Executive Report", className="text-center mb-3"),
                                    html.P("Text summary", className="text-center text-muted mb-3"),
                                    dbc.Button("Generate Report", style={'backgroundColor': COLORS['success'], 'border': 'none'},
                                             className="w-100", href="/download/summary", external_link=True)
                                ])
                            ], style={'border': f"2px solid {COLORS['success']}"})
                        ], width=4),
                    ])
                ])
            ], style={'boxShadow': '0 4px 6px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ])
    ], className="mb-4"),
    
    # Statistics Section
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("📊 Collection Statistics", style={'color': COLORS['primary'], 'marginBottom': '20px'}),
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.H2(str(incidents), style={'color': COLORS['primary'], 'fontWeight': 'bold'}),
                                html.P("Total Incidents Collected", style={'color': '#6B7280'})
                            ], className="text-center")
                        ], width=3),
                        dbc.Col([
                            html.Div([
                                html.H2(str(mappings), style={'color': COLORS['accent'], 'fontWeight': 'bold'}),
                                html.P("MITRE ATT&CK Mappings", style={'color': '#6B7280'})
                            ], className="text-center")
                        ], width=3),
                        dbc.Col([
                            html.Div([
                                html.H2("3", style={'color': COLORS['success'], 'fontWeight': 'bold'}),
                                html.P("Classification Dimensions", style={'color': '#6B7280'})
                            ], className="text-center")
                        ], width=3),
                        dbc.Col([
                            html.Div([
                                html.H2("6", style={'color': COLORS['warning'], 'fontWeight': 'bold'}),
                                html.P("Active Data Sources", style={'color': '#6B7280'})
                            ], className="text-center")
                        ], width=3),
                    ])
                ])
            ], style={'boxShadow': '0 4px 6px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px'})
        ])
    ], className="mb-4"),
    
    # Research Foundation
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("🎓 Research Foundation", style={'color': COLORS['primary'], 'marginBottom': '15px'}),
                    html.Ul([
                        html.Li("Based on systematic review of 74 academic papers (Nov 2023)"),
                        html.Li("Addresses identified gap: 'lack of standardized cyber impact taxonomy'"),
                        html.Li("Integrates MITRE ATT&CK Framework for Financial Services"),
                        html.Li("Multi-dimensional classification: Technology, Human, Procedural"),
                        html.Li("Real-time data from 6+ cybersecurity intelligence sources")
                    ], style={'color': '#6B7280', 'lineHeight': '2'})
                ])
            ], style={'boxShadow': '0 4px 6px rgba(0,0,0,0.1)', 'border': 'none', 'borderRadius': '12px',
                     'backgroundColor': '#F0F9FF'})
        ])
    ])
    
], fluid=True, style={'padding': '20px', 'maxWidth': '1400px', 'margin': '0 auto'})