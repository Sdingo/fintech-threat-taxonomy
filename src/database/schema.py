import sqlite3
from datetime import datetime
import os

class ThreatDatabase:
    """Database manager for FinTech threat taxonomy"""
    
    def __init__(self, db_path='data/threats.db'):
        self.db_path = db_path
        self.conn = None
        self.ensure_database_exists()
    
    def ensure_database_exists(self):
        """Create database directory if it doesn't exist"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    def connect(self):
        """Connect to SQLite database"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable column access by name
        return self.conn
    
    def create_tables(self):
        """Create all necessary tables"""
        self.connect()
        cursor = self.conn.cursor()
        
        # Main incidents table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            date_discovered DATE NOT NULL,
            date_reported DATE,
            source_url TEXT,
            source_type TEXT,  -- 'news', 'cve', 'breach_notification', 'threat_feed'
            
            -- FinTech specific
            subsector TEXT,  -- 'digital_banking', 'payment_processor', 'crypto_exchange', etc.
            company_name TEXT,
            company_country TEXT,
            
            -- Impact metrics
            records_affected INTEGER,
            estimated_cost_usd REAL,
            downtime_hours REAL,
            
            -- Status
            status TEXT DEFAULT 'active',  -- 'active', 'resolved', 'ongoing'
            severity TEXT,  -- 'critical', 'high', 'medium', 'low'
            
            -- Metadata
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            -- Classification confidence
            classification_confidence REAL DEFAULT 0.0
        )
        ''')
        
        # Threat classifications (multi-dimensional taxonomy)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_classifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            
            -- Dimension 1: Technology-based threats
            tech_category TEXT,  -- 'malware', 'network', 'application', 'cloud', 'emerging'
            tech_subcategory TEXT,  -- 'ransomware', 'ddos', 'api_vulnerability', etc.
            
            -- Dimension 2: Human-originated threats
            human_category TEXT,  -- 'social_engineering', 'insider', 'credential_based'
            human_subcategory TEXT,  -- 'phishing', 'malicious_insider', 'credential_stuffing'
            
            -- Dimension 3: Procedural threats
            procedural_category TEXT,  -- 'compliance', 'access_control', 'incident_response'
            procedural_subcategory TEXT,
            
            -- Classification metadata
            classified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            classification_method TEXT,  -- 'automated', 'manual', 'hybrid'
            confidence_score REAL,
            
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        )
        ''')
        
        # MITRE ATT&CK mappings
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS mitre_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            
            -- MITRE ATT&CK details
            tactic_id TEXT,  -- 'TA0001', 'TA0002', etc.
            tactic_name TEXT,  -- 'Initial Access', 'Execution', etc.
            technique_id TEXT,  -- 'T1078', 'T1566', etc.
            technique_name TEXT,  -- 'Valid Accounts', 'Phishing', etc.
            sub_technique_id TEXT,  -- 'T1078.001', etc.
            sub_technique_name TEXT,
            
            -- Confidence
            confidence REAL DEFAULT 0.5,
            mapping_source TEXT,  -- 'automated', 'manual', 'ml_prediction'
            
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        )
        ''')
        
        # Regulatory impact table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS regulatory_impact (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            
            -- Regulations affected
            regulation_name TEXT,  -- 'GDPR', 'PSD2', 'DORA', 'SOX', 'GLBA'
            violation_type TEXT,
            fine_amount_usd REAL,
            notification_required BOOLEAN,
            notification_deadline_hours INTEGER,
            
            -- Compliance status
            reported_to_regulator BOOLEAN DEFAULT 0,
            report_date DATE,
            
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        )
        ''')
        
        # Financial impact breakdown
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS financial_impact (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            
            -- Cost breakdown
            direct_costs REAL,  -- Ransom, recovery, system replacement
            operational_costs REAL,  -- Downtime, degraded service
            reputational_costs REAL,  -- Customer churn, brand damage
            legal_costs REAL,  -- Lawsuits, investigations
            regulatory_fines REAL,
            
            -- Total
            total_estimated_cost REAL,
            cost_calculation_method TEXT,
            calculation_confidence REAL,
            
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        )
        ''')
        
        # Data sources tracking
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS data_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT UNIQUE NOT NULL,
            source_type TEXT,  -- 'rss', 'api', 'manual', 'scraper'
            source_url TEXT,
            last_checked TIMESTAMP,
            items_collected INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            check_frequency_hours INTEGER DEFAULT 24
        )
        ''')
        
        self.conn.commit()
        print("Database tables created successfully!")
        
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

# Initialize database when module is imported
if __name__ == "__main__":
    db = ThreatDatabase()
    db.create_tables()
    db.close()
    print("\n Database initialized at: data/threats.db")