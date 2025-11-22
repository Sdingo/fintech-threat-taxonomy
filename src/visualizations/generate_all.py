"""
Generate all visualizations at once
"""
from mitre_heatmap import create_mitre_heatmap
from technique_chart import create_technique_chart

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("🎨 GENERATING ALL VISUALIZATIONS")
    print("=" * 70)
    
    print("\n1. Creating MITRE ATT&CK Heatmap...")
    create_mitre_heatmap()
    
    print("\n2. Creating Technique Frequency Chart...")
    create_technique_chart()
    
    print("\n" + "=" * 70)
    print("✅ ALL VISUALIZATIONS COMPLETE!")
    print("=" * 70)
    print("\n📁 Check the 'reports/' folder for HTML files")
    print("   - mitre_heatmap.html")
    print("   - technique_frequency.html")
    print("   - attack_navigator.json (import to MITRE Navigator)")
    print("\n🌐 Open HTML files in your browser for interactive charts!")
    print("=" * 70 + "\n")