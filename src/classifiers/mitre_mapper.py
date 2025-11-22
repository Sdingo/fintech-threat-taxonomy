"""
MITRE ATT&CK Technique Mapper
Maps FinTech threats to MITRE ATT&CK TTPs (Tactics, Techniques, Procedures)
Based on: MITRE Enhanced Cyber Threat Model for Financial Services (2024)
"""
import sqlite3
from datetime import datetime
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from config.taxonomy import MITRE_MAPPING

class MITREMapper:
    """Maps incidents to MITRE ATT&CK techniques"""
    
    # MITRE ATT&CK Tactics (the "why" of an attack)
    TACTICS = {
        'TA0001': 'Initial Access',
        'TA0002': 'Execution',
        'TA0003': 'Persistence',
        'TA0004': 'Privilege Escalation',
        'TA0005': 'Defense Evasion',
        'TA0006': 'Credential Access',
        'TA0007': 'Discovery',
        'TA0008': 'Lateral Movement',
        'TA0009': 'Collection',
        'TA0010': 'Exfiltration',
        'TA0011': 'Command and Control',
        'TA0040': 'Impact'
    }
    
    def __init__(self, db_path='data/threats.db'):
        self.db_path = db_path
    
    def map_all_unmapped(self):
        """Map all incidents that haven't been mapped to MITRE yet"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get unmapped incidents
        cursor.execute('''
            SELECT * FROM incidents
            WHERE incident_id NOT IN (
                SELECT DISTINCT incident_id FROM mitre_mappings
            )
        ''')
        
        incidents = cursor.fetchall()
        print(f"\n🎯 Found {len(incidents)} unmapped incidents")
        
        mapped_count = 0
        total_techniques = 0
        
        for incident in incidents:
            techniques = self.map_incident_to_mitre(incident)
            if techniques > 0:
                mapped_count += 1
                total_techniques += techniques
        
        conn.close()
        
        print(f"\n✅ Mapped {mapped_count}/{len(incidents)} incidents")
        print(f"📊 Total MITRE techniques identified: {total_techniques}")
        
        return mapped_count
    
    def map_incident_to_mitre(self, incident):
        """
        Map a single incident to MITRE ATT&CK techniques
        
        Args:
            incident: sqlite3.Row object with incident data
            
        Returns:
            Number of techniques mapped
        """
        # Combine title and description for analysis
        text = f"{incident['title']} {incident['description'] or ''}".lower()
        
        matched_techniques = []
        
        # Check each MITRE technique
        for technique_id, technique_data in MITRE_MAPPING.items():
            # Count keyword matches
            matches = sum(1 for keyword in technique_data['keywords'] if keyword in text)
            
            if matches > 0:
                # Calculate confidence based on keyword matches
                confidence = min(matches * 0.3, 1.0)  # Max out at 1.0
                confidence = max(confidence, technique_data['confidence'] * 0.5)  # Use base confidence
                
                matched_techniques.append({
                    'technique_id': technique_id,
                    'technique_name': technique_data['name'],
                    'tactic_id': technique_data['tactic'],
                    'tactic_name': self.TACTICS.get(technique_data['tactic'], 'Unknown'),
                    'confidence': confidence,
                    'matches': matches
                })
        
        # Save to database
        if matched_techniques:
            self._save_mappings(incident['incident_id'], matched_techniques)
            
            print(f"\n  📍 {incident['title'][:60]}")
            for tech in sorted(matched_techniques, key=lambda x: x['confidence'], reverse=True)[:3]:
                print(f"     → {tech['technique_id']}: {tech['technique_name']} "
                      f"({tech['tactic_name']}) - Confidence: {tech['confidence']:.2f}")
        
        return len(matched_techniques)
    
    def _save_mappings(self, incident_id, techniques):
        """Save MITRE mappings to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for tech in techniques:
            try:
                cursor.execute('''
                    INSERT INTO mitre_mappings (
                        incident_id, tactic_id, tactic_name,
                        technique_id, technique_name, 
                        confidence, mapping_source, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident_id,
                    tech['tactic_id'],
                    tech['tactic_name'],
                    tech['technique_id'],
                    tech['technique_name'],
                    tech['confidence'],
                    'automated_keyword',
                    datetime.now()
                ))
            except sqlite3.IntegrityError:
                # Duplicate mapping, skip
                continue
        
        conn.commit()
        conn.close()
    
    def get_attack_matrix_summary(self):
        """Generate ATT&CK matrix summary for visualization"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                tactic_name,
                technique_id,
                technique_name,
                COUNT(*) as incident_count,
                AVG(confidence) as avg_confidence
            FROM mitre_mappings
            GROUP BY tactic_name, technique_id, technique_name
            ORDER BY incident_count DESC
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        return results
    
    def generate_attack_navigator_json(self, output_file='reports/attack_navigator.json'):
        """
        Generate MITRE ATT&CK Navigator JSON
        Can be imported into: https://mitre-attack.github.io/attack-navigator/
        """
        import json
        import os
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                technique_id,
                COUNT(*) as count,
                AVG(confidence) as avg_confidence
            FROM mitre_mappings
            GROUP BY technique_id
        ''')
        
        techniques = cursor.fetchall()
        conn.close()
        
        # Build ATT&CK Navigator layer
        layer = {
            "name": "FinTech Threat Taxonomy - Real Incidents",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"Real FinTech cyber threats mapped to MITRE ATT&CK (Generated: {datetime.now().strftime('%Y-%m-%d')})",
            "filters": {
                "platforms": ["Windows", "Linux", "macOS", "Network", "Cloud"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True
            },
            "hideDisabled": False,
            "techniques": []
        }
        
        # Add techniques with scores
        for tech in techniques:
            technique_id = tech[0]
            count = tech[1]
            confidence = tech[2]
            
            # Calculate score (0-100) based on frequency and confidence
            score = min((count * 10) + (confidence * 50), 100)
            
            layer['techniques'].append({
                "techniqueID": technique_id,
                "score": score,
                "color": self._get_color_for_score(score),
                "comment": f"Incidents: {count}, Avg Confidence: {confidence:.2f}",
                "enabled": True,
                "metadata": []
            })
        
        # Ensure reports directory exists
        os.makedirs('reports', exist_ok=True)
        
        # Save JSON
        with open(output_file, 'w') as f:
            json.dump(layer, f, indent=2)
        
        print(f"\n📊 ATT&CK Navigator layer saved: {output_file}")
        print(f"   Import at: https://mitre-attack.github.io/attack-navigator/")
        
        return output_file
    
    def _get_color_for_score(self, score):
        """Get color based on threat score"""
        if score >= 75:
            return "#ff0000"  # Red - Critical
        elif score >= 50:
            return "#ff6600"  # Orange - High
        elif score >= 25:
            return "#ffcc00"  # Yellow - Medium
        else:
            return "#00cc00"  # Green - Low

# Run MITRE mapper
if __name__ == "__main__":
    print("=" * 70)
    print(" MITRE ATT&CK MAPPER FOR FINTECH")
    print("=" * 70)
    print("\nMapping incidents to MITRE ATT&CK framework...")
    print("Based on: Top 10 techniques targeting financial services (2024)\n")
    
    mapper = MITREMapper()
    mapper.map_all_unmapped()
    
    # Generate summary
    print("\n" + "=" * 70)
    print(" ATT&CK MATRIX SUMMARY")
    print("=" * 70)
    
    summary = mapper.get_attack_matrix_summary()
    
    print(f"\n{'TACTIC':<20} {'TECHNIQUE ID':<15} {'TECHNIQUE NAME':<30} {'COUNT':<10}")
    print("-" * 80)
    
    for row in summary[:15]:  # Top 15
        print(f"{row[0]:<20} {row[1]:<15} {row[2]:<30} {row[3]:<10}")
    
    # Generate ATT&CK Navigator JSON
    print("\n" + "=" * 70)
    mapper.generate_attack_navigator_json()
    
    print("\n MITRE mapping complete!")
    print("=" * 70)