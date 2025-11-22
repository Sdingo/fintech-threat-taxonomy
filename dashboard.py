"""
FinTech Cyber Threat Taxonomy Dashboard
Multi-page application with professional UX/UI
"""
import dash
from dash import dcc, html, Input, Output, callback
import dash_bootstrap_components as dbc

# Initialize Dash app with FLATLY theme (modern, professional)
app = dash.Dash(
    __name__, 
    external_stylesheets=[dbc.themes.FLATLY],
    suppress_callback_exceptions=True,
    use_pages=False  # We'll handle pages manually
)
app.title = "FinTech Threat Intelligence"

# Professional FinTech Color Scheme
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

# Create navbar
def create_navbar():
    return dbc.Navbar(
        dbc.Container([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Span("🛡️", style={'fontSize': '28px', 'marginRight': '10px'}),
                        dbc.NavbarBrand("FinTech Threat Intelligence", 
                                       style={'fontSize': '24px', 'fontWeight': 'bold'})
                    ], style={'display': 'flex', 'alignItems': 'center'})
                ], width="auto"),
            ], align="center", className="g-0"),
            
            dbc.Nav([
                dbc.NavItem(dbc.NavLink("📊 Overview", href="/", id="nav-overview", 
                                       style={'fontSize': '16px', 'fontWeight': '500'})),
                dbc.NavItem(dbc.NavLink("🎯 MITRE ATT&CK", href="/mitre", id="nav-mitre",
                                       style={'fontSize': '16px', 'fontWeight': '500'})),
                dbc.NavItem(dbc.NavLink("🧠 Taxonomy", href="/taxonomy", id="nav-taxonomy",
                                       style={'fontSize': '16px', 'fontWeight': '500'})),
                dbc.NavItem(dbc.NavLink("📈 Analytics", href="/analytics", id="nav-analytics",
                                       style={'fontSize': '16px', 'fontWeight': '500'})),
                dbc.NavItem(dbc.NavLink("🔄 Data Collection", href="/collection", id="nav-collection",
                                       style={'fontSize': '16px', 'fontWeight': '500'})),
            ], navbar=True, className="ms-auto")
        ], fluid=True),
        color=COLORS['primary'],
        dark=True,
        sticky="top",
        style={'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}
    )

# App layout with URL routing and auto-refresh
app.layout = html.Div([
    dcc.Interval(
        id='interval-component',
        interval=5*60*1000,  # 5 minutes in milliseconds
        n_intervals=0
    ),
    dcc.Location(id='url', refresh=False),
    create_navbar(),
    html.Div(id='page-content', style={
        'backgroundColor': COLORS['light'],
        'minHeight': 'calc(100vh - 56px)',
        'padding': '0'
    })
])

# Import page modules
from pages import overview, mitre, taxonomy, analytics, data_collection

# Callback for page routing
@app.callback(
    Output('page-content', 'children'),
    [Input('url', 'pathname')]
)
def display_page(pathname):
    if pathname == '/mitre':
        return mitre.layout
    elif pathname == '/taxonomy':
        return taxonomy.layout
    elif pathname == '/analytics':
        return analytics.layout
    elif pathname == '/collection':
        return data_collection.layout
    else:
        return overview.layout

# Run server
if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("🛡️  FinTech Threat Intelligence Dashboard")
    print("=" * 70)
    print("\n✨ Professional multi-page dashboard with navigation")
    print("🌐 Open: http://127.0.0.1:8050")
    print("⌨️  Press Ctrl+C to stop\n")
    print("=" * 70 + "\n")
    
    app.run(debug=True, port=8050, host='127.0.0.1')