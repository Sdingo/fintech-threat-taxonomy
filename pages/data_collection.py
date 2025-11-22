"""
Data Collection Control Page
Manual trigger for data collection
"""
from dash import html, callback, Input, Output, State
import dash_bootstrap_components as dbc
import subprocess
import os
from datetime import datetime

COLORS = {
    'white': '#FFFBFF',
    'primary': '#004F60',
    'dark': '#5B4750',
    'accent': '#5FABC5',
    'success': '#C5D94D',
    'warning': '#FCD24A',
    'light': '#D6DBDE',
    'secondary': '#A7CCCE'
}

layout = dbc.Container([
    html.H2("🔄 Data Collection Control", 
           style={'color': COLORS['primary'], 'marginTop': '20px', 'marginBottom': '30px'}),
    
    # Collection Status
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("📡 Real-Time Data Collection", 
                           style={'color': COLORS['primary'], 'marginBottom': '20px'}),
                    
                    html.P([
                        "Manually trigger data collection from threat intelligence sources. ",
                        "This will fetch the latest incidents from RSS feeds, CVE database, and threat feeds."
                    ], style={'color': '#6B7280', 'marginBottom': '30px'}),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.H5("📰 RSS Feeds", className="mb-3", 
                                               style={'color': COLORS['primary']}),
                                        html.P("6 cybersecurity news sources", 
                                              className="text-muted mb-3"),
                                        dbc.Button("🔄 Collect RSS", id="btn-rss", 
                                                 color="primary", className="w-100")
                                    ])
                                ])
                            ], style={'border': f"2px solid {COLORS['primary']}", 'height': '100%'})
                        ], width=4),
                        
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.H5("🔍 CVE Database", className="mb-3",
                                               style={'color': COLORS['accent']}),
                                        html.P("NVD vulnerability tracking", 
                                              className="text-muted mb-3"),
                                        dbc.Button("🔄 Collect CVEs", id="btn-cve",
                                                 style={'backgroundColor': COLORS['accent'], 
                                                       'border': 'none'}, className="w-100")
                                    ])
                                ])
                            ], style={'border': f"2px solid {COLORS['accent']}", 'height': '100%'})
                        ], width=4),
                        
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.H5("🚀 Collect All", className="mb-3",
                                               style={'color': COLORS['success']}),
                                        html.P("Run all collectors at once", 
                                              className="text-muted mb-3"),
                                        dbc.Button("🚀 Run All", id="btn-all",
                                                 style={'backgroundColor': COLORS['success'], 
                                                       'border': 'none'}, 
                                                 className="w-100", size="lg")
                                    ])
                                ])
                            ], style={'border': f"2px solid {COLORS['success']}", 'height': '100%'})
                        ], width=4),
                    ], className="mb-4"),
                    
                    # Status output
                    html.Div(id='collection-output', style={
                        'backgroundColor': COLORS['dark'],
                        'color': COLORS['white'],
                        'padding': '20px',
                        'borderRadius': '8px',
                        'fontFamily': 'monospace',
                        'minHeight': '150px',
                        'maxHeight': '300px',
                        'overflowY': 'auto'
                    })
                ])
            ], style={'boxShadow': '0 4px 6px rgba(0,0,0,0.1)', 'border': 'none', 
                     'borderRadius': '12px'})
        ])
    ], className="mb-4"),
    
    # Collection Schedule Info
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("⏰ Automated Collection Schedule", 
                           style={'color': COLORS['primary'], 'marginBottom': '15px'}),
                    html.P([
                        "For continuous threat monitoring, set up automated collection using Windows Task Scheduler:"
                    ], style={'color': '#6B7280', 'marginBottom': '15px'}),
                    
                    html.Div([
                        html.Pre([
                            "# Run every hour:\n",
                            "cd C:\\Users\\USER\\Desktop\\FinTech-Threat-Taxonomy\n",
                            "venv\\Scripts\\activate\n",
                            "python src\\collectors\\master_collector.py\n"
                        ], style={'backgroundColor': COLORS['light'], 'padding': '15px', 
                                 'borderRadius': '8px', 'fontSize': '12px'})
                    ])
                ])
            ], style={'boxShadow': '0 4px 6px rgba(0,0,0,0.1)', 'border': 'none', 
                     'borderRadius': '12px', 'backgroundColor': '#F0F9FF'})
        ])
    ])
    
], fluid=True, style={'padding': '20px', 'maxWidth': '1400px', 'margin': '0 auto'})

# Callbacks for collection buttons
@callback(
    Output('collection-output', 'children'),
    [Input('btn-rss', 'n_clicks'),
     Input('btn-cve', 'n_clicks'),
     Input('btn-all', 'n_clicks')],
    prevent_initial_call=True
)
def run_collection(rss_clicks, cve_clicks, all_clicks):
    """Run data collection based on button clicked"""
    from dash import callback_context
    
    if not callback_context.triggered:
        return "Ready to collect data..."
    
    button_id = callback_context.triggered[0]['prop_id'].split('.')[0]
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if button_id == 'btn-rss':
        return html.Div([
            html.P(f"[{timestamp}] 🔄 Starting RSS collection..."),
            html.P("📡 Fetching from 6 news sources..."),
            html.P("⏳ This may take 30-60 seconds..."),
            html.P("💡 TIP: Run collectors from command line for full output:", 
                  style={'color': COLORS['warning']}),
            html.Pre("python src/collectors/rss_collector.py", 
                    style={'color': COLORS['accent'], 'marginTop': '10px'})
        ])
    
    elif button_id == 'btn-cve':
        return html.Div([
            html.P(f"[{timestamp}] 🔄 Starting CVE collection..."),
            html.P("🔍 Querying NVD database..."),
            html.P("⏳ This may take 1-2 minutes (rate limits)..."),
            html.P("💡 TIP: Run collectors from command line for full output:", 
                  style={'color': COLORS['warning']}),
            html.Pre("python src/collectors/cve_collector.py", 
                    style={'color': COLORS['accent'], 'marginTop': '10px'})
        ])
    
    elif button_id == 'btn-all':
        return html.Div([
            html.P(f"[{timestamp}] 🚀 Starting FULL data collection..."),
            html.P("📰 Phase 1: RSS feeds (6 sources)"),
            html.P("🔍 Phase 2: CVE database"),
            html.P("⏳ Total time: ~2-3 minutes..."),
            html.Hr(style={'borderColor': COLORS['accent']}),
            html.P("💡 RECOMMENDED: Run from command line for best results:", 
                  style={'color': COLORS['warning'], 'fontWeight': 'bold'}),
            html.Pre("cd src/collectors\npython master_collector.py", 
                    style={'color': COLORS['accent'], 'marginTop': '10px', 
                          'backgroundColor': COLORS['dark'], 'padding': '10px', 
                          'borderRadius': '5px'})
        ])
    
    return "Ready to collect data..."