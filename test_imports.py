# Test all imports
try:
    import feedparser
    print("✅ feedparser imported successfully")
    print(f"   Version: {feedparser.__version__}")
except ImportError as e:
    print(f"❌ feedparser error: {e}")

try:
    import requests
    print("✅ requests imported successfully")
except ImportError as e:
    print(f"❌ requests error: {e}")

try:
    import pandas
    print("✅ pandas imported successfully")
except ImportError as e:
    print(f"❌ pandas error: {e}")

try:
    from bs4 import BeautifulSoup
    print("✅ beautifulsoup4 imported successfully")
except ImportError as e:
    print(f"❌ beautifulsoup4 error: {e}")

print("\n🎉 All core dependencies ready!")