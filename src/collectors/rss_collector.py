import feedparser
import requests
from datetime import datetime, timedelta
import sqlite3
import hashlib
import re
from bs4 import BeautifulSoup

class RSSCollector:
    """Collects cyber threat news from RSS feeds"""
    
    # FinTech-focused cybersecurity news sources
    RSS_FEEDS = {
        'the_record': 'https://therecord.media/feed',
        'krebs': 'https://krebsonsecurity.com/feed/',
        'bleeping_computer': 'https://www.bleepingcomputer.com/feed/',
        'security_week': 'https://www.securityweek.com/feed/',
        'dark_reading': 'https://www.darkreading.com/rss.xml',
        'threatpost': 'https://threatpost.com/feed/',
    }
    
    # Keywords to identify FinTech-related incidents
    FINTECH_KEYWORDS = [
        'bank', 'banking', 'fintech', 'financial', 'payment', 'crypto',
        'cryptocurrency', 'bitcoin', 'blockchain', 'wallet', 'exchange',
        'lending', 'insurance', 'insurtech', 'neobank', 'paypal', 'stripe',
        'visa', 'mastercard', 'swift', 'atm', 'pos', 'card', 'fraud',
        'transaction', 'financial institution', 'credit union', 'brokerage'
    ]
    
    def __init__(self, db_path='data/threats.db'):
        self.db_path = db_path
    
    def collect_from_feed(self, feed_name, feed_url, days_back=30):
        """
        Collect articles from a single RSS feed
        
        Args:
            feed_name: Name of the feed source
            feed_url: URL of the RSS feed
            days_back: How many days of articles to collect
        """
        print(f"\n📡 Fetching from {feed_name}...")
        
        try:
            feed = feedparser.parse(feed_url)
            
            if feed.bozo:
                print(f"⚠️  Warning: Feed may be malformed")
            
            articles = []
            cutoff_date = datetime.now() - timedelta(days=days_back)
            
            for entry in feed.entries:
                # Parse publication date
                pub_date = self._parse_date(entry)
                
                if pub_date and pub_date < cutoff_date:
                    continue
                
                # Check if article is FinTech-related
                title = entry.get('title', '')
                description = entry.get('summary', '')
                content = f"{title} {description}".lower()
                
                if self._is_fintech_related(content):
                    article = {
                        'title': title,
                        'description': description,
                        'url': entry.get('link', ''),
                        'published': pub_date,
                        'source': feed_name
                    }
                    articles.append(article)
            
            print(f" Found {len(articles)} FinTech-related articles")
            return articles
            
        except Exception as e:
            print(f" Error fetching {feed_name}: {str(e)}")
            return []
    
    def collect_all_feeds(self, days_back=30):
        """Collect from all configured RSS feeds"""
        all_articles = []
        
        for feed_name, feed_url in self.RSS_FEEDS.items():
            articles = self.collect_from_feed(feed_name, feed_url, days_back)
            all_articles.extend(articles)
        
        print(f"\n Total FinTech articles collected: {len(all_articles)}")
        return all_articles
    
    def save_to_database(self, articles):
        """Save collected articles to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        saved_count = 0
        duplicate_count = 0
        
        for article in articles:
            # Generate unique incident ID from URL
            incident_id = self._generate_incident_id(article['url'])
            
            try:
                cursor.execute('''
                INSERT INTO incidents (
                    incident_id, title, description, date_discovered,
                    source_url, source_type, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident_id,
                    article['title'],
                    article['description'],
                    article['published'],
                    article['url'],
                    'news',
                    'active',
                    datetime.now()
                ))
                saved_count += 1
                
            except sqlite3.IntegrityError:
                # Duplicate incident_id
                duplicate_count += 1
                continue
        
        conn.commit()
        conn.close()
        
        print(f"\n💾 Saved {saved_count} new incidents")
        print(f" Skipped {duplicate_count} duplicates")
        
        return saved_count
    
    def _is_fintech_related(self, text):
        """Check if text contains FinTech-related keywords"""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.FINTECH_KEYWORDS)
    
    def _parse_date(self, entry):
        """Parse publication date from feed entry"""
        date_fields = ['published_parsed', 'updated_parsed', 'created_parsed']
        
        for field in date_fields:
            if hasattr(entry, field):
                date_tuple = getattr(entry, field)
                if date_tuple:
                    try:
                        return datetime(*date_tuple[:6])
                    except:
                        pass
        
        return datetime.now()
    
    def _generate_incident_id(self, url):
        """Generate unique incident ID from URL"""
        return hashlib.md5(url.encode()).hexdigest()[:16]

# Test the collector
if __name__ == "__main__":
    collector = RSSCollector()
    
    print("🚀 Starting RSS collection...")
    articles = collector.collect_all_feeds(days_back=7)
    
    if articles:
        collector.save_to_database(articles)
        print("\n Collection complete!")
    else:
        print("\n⚠️  No articles found")