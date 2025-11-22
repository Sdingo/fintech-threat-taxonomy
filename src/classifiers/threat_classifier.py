"""
Multi-dimensional threat classifier
Implements the 3-dimensional taxonomy from research
"""
import sqlite3
from datetime import datetime
import sys
import os

# Add config to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from config.taxonomy import (
    TECH_TAXONOMY, HUMAN_TAXONOMY, PROCEDURAL_TAXONOMY,
    FINTECH_SUBSECTORS, MITRE_MAPPING, SEVERITY_RULES
)

class ThreatClassifier:
    """Classifies cyber threats using multi-dimensional taxonomy"""
    
    def __init__(self, db_path='data/threats.db'):
        self.db_path = db_path
    
    def classify_all_unclassified(self):
        """Classify all incidents that haven't been classified yet"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get unclassified incidents
        cursor.execute('''
            SELECT * FROM incidents
            WHERE incident_id NOT IN (
                SELECT DISTINCT incident_id FROM threat_classifications
            )
        ''')
        
        incidents = cursor.fetchall()
        print(f"\n🔍 Found {len(incidents)} unclassified incidents")
        
        classified_count = 0
        for incident in incidents:
            if self.classify_incident(incident):
                classified_count += 1
        
        conn.close()
        print(f"\n✅ Classified {classified_count}/{len(incidents)} incidents")
        
        return classified_count
    
    def classify_incident(self, incident):
        """
        Classify a single incident across all 3 dimensions
        
        Args:
            incident: sqlite3.Row object with incident data
        """
        # Combine title and description for analysis
        text = f"{incident['title']} {incident['description'] or ''}".lower()
        
        # Dimension 1: Technology-based threats
        tech_cat, tech_subcat, tech_confidence = self._classify_technology(text)
        
        # Dimension 2: Human-originated threats
        human_cat, human_subcat, human_confidence = self._classify_human(text)
        
        # Dimension 3: Procedural threats
        proc_cat, proc_subcat, proc_confidence = self._classify_procedural(text)
        
        # Determine overall confidence
        avg_confidence = (tech_confidence + human_confidence + proc_confidence) / 3
        
        # Save classification
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO threat_classifications (
                    incident_id, tech_category, tech_subcategory,
                    human_category, human_subcategory,
                    procedural_category, procedural_subcategory,
                    classification_method, confidence_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident['incident_id'],
                tech_cat, tech_subcat,
                human_cat, human_subcat,
                proc_cat, proc_subcat,
                'automated',
                avg_confidence
            ))
            
            conn.commit()
            
            print(f"  ✅ {incident['title'][:50]}...")
            print(f"     Tech: {tech_cat}/{tech_subcat}")
            print(f"     Human: {human_cat}/{human_subcat}")
            print(f"     Proc: {proc_cat}/{proc_subcat}")
            print(f"     Confidence: {avg_confidence:.2f}")
            
            return True
            
        except sqlite3.IntegrityError:
            print(f"  ⏭️  Already classified: {incident['title'][:50]}")
            return False
        
        finally:
            conn.close()
    
    def _classify_technology(self, text):
        """Classify technology-based threat dimension"""
        best_category = None
        best_subcategory = None
        best_score = 0
        
        for category, data in TECH_TAXONOMY.items():
            # Check main keywords
            category_score = sum(1 for kw in data['keywords'] if kw in text)
            
            # Check subcategories
            for subcat, subcat_keywords in data['subcategories'].items():
                subcat_score = sum(1 for kw in subcat_keywords if kw in text)
                total_score = category_score + subcat_score * 2  # Weight subcategory higher
                
                if total_score > best_score:
                    best_score = total_score
                    best_category = category
                    best_subcategory = subcat
        
        # Calculate confidence (normalize to 0-1)
        confidence = min(best_score / 5.0, 1.0) if best_score > 0 else 0.0
        
        return best_category, best_subcategory, confidence
    
    def _classify_human(self, text):
        """Classify human-originated threat dimension"""
        best_category = None
        best_subcategory = None
        best_score = 0
        
        for category, data in HUMAN_TAXONOMY.items():
            category_score = sum(1 for kw in data['keywords'] if kw in text)
            
            for subcat, subcat_keywords in data['subcategories'].items():
                subcat_score = sum(1 for kw in subcat_keywords if kw in text)
                total_score = category_score + subcat_score * 2
                
                if total_score > best_score:
                    best_score = total_score
                    best_category = category
                    best_subcategory = subcat
        
        confidence = min(best_score / 5.0, 1.0) if best_score > 0 else 0.0
        
        return best_category, best_subcategory, confidence
    
    def _classify_procedural(self, text):
        """Classify procedural threat dimension"""
        best_category = None
        best_subcategory = None
        best_score = 0
        
        for category, data in PROCEDURAL_TAXONOMY.items():
            category_score = sum(1 for kw in data['keywords'] if kw in text)
            
            for subcat, subcat_keywords in data['subcategories'].items():
                subcat_score = sum(1 for kw in subcat_keywords if kw in text)
                total_score = category_score + subcat_score * 2
                
                if total_score > best_score:
                    best_score = total_score
                    best_category = category
                    best_subcategory = subcat
        
        confidence = min(best_score / 5.0, 1.0) if best_score > 0 else 0.0
        
        return best_category, best_subcategory, confidence

# Run classifier
if __name__ == "__main__":
    print("=" * 60)
    print("🧠 THREAT CLASSIFIER - Multi-Dimensional Taxonomy")
    print("=" * 60)
    
    classifier = ThreatClassifier()
    classifier.classify_all_unclassified()
    
    print("\n" + "=" * 60)
    print("✅ Classification complete!")
    print("=" * 60)