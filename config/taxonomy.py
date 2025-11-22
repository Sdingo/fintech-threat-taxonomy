"""
Multi-dimensional threat taxonomy for FinTech cybersecurity
Based on: "Cybersecurity threats in FinTech: A systematic review" (2023)
"""

# DIMENSION 1: TECHNOLOGY-BASED THREATS
TECH_TAXONOMY = {
    'malware': {
        'keywords': ['ransomware', 'trojan', 'malware', 'virus', 'worm', 'spyware', 
                     'backdoor', 'rootkit', 'lockbit', 'blackcat', 'emotet', 'trickbot'],
        'subcategories': {
            'ransomware': ['ransomware', 'lockbit', 'blackcat', 'cl0p', 'encrypt', 'ransom'],
            'banking_trojan': ['emotet', 'trickbot', 'qakbot', 'banking trojan', 'zeus'],
            'info_stealer': ['redline', 'raccoon', 'stealer', 'credential theft'],
            'mobile_malware': ['ngate', 'flubot', 'android malware', 'mobile trojan']
        }
    },
    'network': {
        'keywords': ['ddos', 'dns', 'mitm', 'man-in-the-middle', 'network attack', 
                     'botnet', 'amplification', 'flood'],
        'subcategories': {
            'ddos': ['ddos', 'denial of service', 'dos attack', 'flood'],
            'mitm': ['man-in-the-middle', 'mitm', 'intercept'],
            'dns_attack': ['dns hijack', 'dns poison', 'dns spoof']
        }
    },
    'application': {
        'keywords': ['sql injection', 'xss', 'cross-site', 'vulnerability', 'exploit',
                     'zero-day', 'cve', 'rce', 'remote code execution', 'api'],
        'subcategories': {
            'api_vulnerability': ['api', 'rest', 'endpoint', 'authentication bypass'],
            'sql_injection': ['sql injection', 'sqli', 'database injection'],
            'xss': ['cross-site scripting', 'xss', 'javascript injection'],
            'zero_day': ['zero-day', 'zero day', '0-day', 'unpatched']
        }
    },
    'cloud': {
        'keywords': ['cloud', 's3', 'azure', 'aws', 'misconfiguration', 'container',
                     'kubernetes', 'docker', 'saas', 'supply chain'],
        'subcategories': {
            'cloud_misconfig': ['misconfiguration', 's3 bucket', 'exposed', 'public bucket'],
            'supply_chain': ['supply chain', 'third-party', 'vendor', 'dependency'],
            'saas_vulnerability': ['saas', 'cloud service', 'microsoft 365', 'salesforce']
        }
    },
    'emerging': {
        'keywords': ['ai', 'machine learning', 'ml', 'deepfake', 'quantum', 'iot'],
        'subcategories': {
            'ai_ml': ['ai poisoning', 'adversarial', 'machine learning', 'model'],
            'deepfake': ['deepfake', 'synthetic media', 'voice clone'],
            'iot': ['iot', 'smart device', 'connected device', 'atm camera']
        }
    }
}

# DIMENSION 2: HUMAN-ORIGINATED THREATS
HUMAN_TAXONOMY = {
    'social_engineering': {
        'keywords': ['phishing', 'spear phishing', 'vishing', 'smishing', 'bec', 
                     'business email compromise', 'social engineering', 'pretexting'],
        'subcategories': {
            'phishing': ['phishing', 'phish', 'email attack', 'fake email'],
            'spear_phishing': ['spear phishing', 'targeted phishing', 'whaling'],
            'bec': ['business email compromise', 'bec', 'ceo fraud'],
            'deepfake_fraud': ['deepfake', 'voice clone', 'video manipulation']
        }
    },
    'insider': {
        'keywords': ['insider', 'employee', 'contractor', 'privileged access', 
                     'rogue employee', 'malicious insider', 'negligent'],
        'subcategories': {
            'malicious_insider': ['malicious insider', 'rogue employee', 'sabotage'],
            'negligent': ['negligent', 'accidental', 'mistake', 'misconfiguration'],
            'compromised_account': ['compromised account', 'stolen credentials', 'account takeover']
        }
    },
    'credential_based': {
        'keywords': ['credential', 'password', 'brute force', 'stuffing', 'spray',
                     'stolen password', 'leaked credentials', 'breach dump'],
        'subcategories': {
            'credential_stuffing': ['credential stuffing', 'stuffing attack', 'breach replay'],
            'password_spray': ['password spray', 'spray attack'],
            'brute_force': ['brute force', 'dictionary attack', 'password crack']
        }
    },
    'executive_targeting': {
        'keywords': ['ceo', 'executive', 'c-suite', 'whaling', 'executive', 'vip'],
        'subcategories': {
            'ceo_fraud': ['ceo fraud', 'executive impersonation'],
            'whaling': ['whaling', 'executive phishing'],
            'doxxing': ['doxxing', 'personal information', 'executive data']
        }
    }
}

# DIMENSION 3: PROCEDURAL THREATS
PROCEDURAL_TAXONOMY = {
    'compliance': {
        'keywords': ['gdpr', 'compliance', 'regulation', 'pci', 'dora', 'psd2', 
                     'sox', 'glba', 'violation', 'regulatory'],
        'subcategories': {
            'gdpr': ['gdpr', 'data protection', 'privacy violation'],
            'psd2': ['psd2', 'strong customer authentication', 'sca'],
            'dora': ['dora', 'digital operational resilience'],
            'pci_dss': ['pci', 'payment card', 'card data']
        }
    },
    'access_control': {
        'keywords': ['access control', 'authentication', 'mfa', 'multi-factor',
                     'authorization', 'privilege', 'rbac', 'least privilege'],
        'subcategories': {
            'weak_auth': ['weak authentication', 'no mfa', 'single factor'],
            'excessive_permissions': ['excessive permissions', 'over-privileged', 'admin access'],
            'stale_access': ['stale access', 'orphaned account', 'dormant account']
        }
    },
    'incident_response': {
        'keywords': ['incident response', 'detection', 'monitoring', 'alert',
                     'delay', 'breach notification', 'response time'],
        'subcategories': {
            'no_ir_plan': ['no incident response', 'no ir plan', 'unprepared'],
            'delayed_detection': ['delayed detection', 'late discovery', 'undetected'],
            'poor_communication': ['poor communication', 'notification delay']
        }
    },
    'third_party': {
        'keywords': ['third-party', 'vendor', 'supplier', 'contractor', 'outsource',
                     'third party risk', 'supply chain'],
        'subcategories': {
            'vendor_risk': ['vendor risk', 'third-party risk', 'supplier'],
            'no_vetting': ['inadequate vetting', 'no due diligence'],
            'no_monitoring': ['no monitoring', 'lack of oversight']
        }
    }
}

# FINTECH SUBSECTOR CLASSIFICATION
FINTECH_SUBSECTORS = {
    'digital_banking': ['neobank', 'digital bank', 'online bank', 'revolut', 'n26', 'chime', 'monzo'],
    'payment_processor': ['payment', 'processor', 'stripe', 'square', 'paypal', 'adyen', 'worldpay'],
    'crypto_exchange': ['crypto', 'cryptocurrency', 'bitcoin', 'ethereum', 'exchange', 'coinbase', 'binance'],
    'defi': ['defi', 'decentralized finance', 'smart contract', 'uniswap', 'compound'],
    'lending': ['lending', 'loan', 'credit', 'p2p lending', 'lendingclub', 'kabbage'],
    'insurtech': ['insurance', 'insurtech', 'lemonade', 'root insurance'],
    'wealthtech': ['wealth', 'investment', 'robo-advisor', 'betterment', 'wealthfront'],
    'regtech': ['regtech', 'compliance tech', 'kyc', 'aml', 'onfido'],
    'infrastructure': ['plaid', 'truelayer', 'fintech infrastructure', 'banking api']
}

# MITRE ATT&CK TECHNIQUE MAPPING
# Top 10 techniques targeting financial services (from research)
MITRE_MAPPING = {
    'T1078': {
        'name': 'Valid Accounts',
        'tactic': 'TA0001',  # Initial Access
        'keywords': ['valid account', 'credential', 'stolen password', 'compromised account'],
        'confidence': 0.8
    },
    'T1566': {
        'name': 'Phishing',
        'tactic': 'TA0001',  # Initial Access
        'keywords': ['phishing', 'phish', 'spear phishing', 'email attack'],
        'confidence': 0.9
    },
    'T1190': {
        'name': 'Exploit Public-Facing Application',
        'tactic': 'TA0001',  # Initial Access
        'keywords': ['exploit', 'vulnerability', 'cve', 'zero-day', 'public-facing'],
        'confidence': 0.85
    },
    'T1486': {
        'name': 'Data Encrypted for Impact',
        'tactic': 'TA0040',  # Impact
        'keywords': ['ransomware', 'encrypt', 'lockbit', 'blackcat', 'ransom'],
        'confidence': 0.95
    },
    'T1657': {
        'name': 'Financial Theft',
        'tactic': 'TA0040',  # Impact
        'keywords': ['financial theft', 'fraud', 'unauthorized transaction', 'wire transfer'],
        'confidence': 0.9
    },
    'T1003': {
        'name': 'Credential Dumping',
        'tactic': 'TA0006',  # Credential Access
        'keywords': ['credential dump', 'password dump', 'mimikatz', 'lsass'],
        'confidence': 0.85
    },
    'T1021': {
        'name': 'Remote Services',
        'tactic': 'TA0008',  # Lateral Movement
        'keywords': ['rdp', 'remote desktop', 'ssh', 'remote access'],
        'confidence': 0.8
    },
    'T1071': {
        'name': 'Command and Control',
        'tactic': 'TA0011',  # Command and Control
        'keywords': ['c2', 'command and control', 'beacon', 'callback'],
        'confidence': 0.75
    },
    'T1041': {
        'name': 'Exfiltration',
        'tactic': 'TA0010',  # Exfiltration
        'keywords': ['exfiltration', 'data theft', 'stolen data', 'data breach'],
        'confidence': 0.85
    },
    'T1547': {
        'name': 'Boot or Logon Autostart Execution',
        'tactic': 'TA0003',  # Persistence
        'keywords': ['persistence', 'autostart', 'registry', 'startup'],
        'confidence': 0.7
    }
}

# SEVERITY SCORING RULES
SEVERITY_RULES = {
    'critical': {
        'keywords': ['ransomware', 'zero-day', 'rce', 'remote code execution', 
                     'critical vulnerability', 'active exploit'],
        'cvss_min': 9.0
    },
    'high': {
        'keywords': ['data breach', 'credential dump', 'privilege escalation',
                     'unauthorized access', 'malware'],
        'cvss_min': 7.0
    },
    'medium': {
        'keywords': ['phishing', 'vulnerability', 'misconfiguration', 'denial of service'],
        'cvss_min': 4.0
    },
    'low': {
        'keywords': ['informational', 'advisory', 'warning', 'best practice'],
        'cvss_min': 0.1
    }
}