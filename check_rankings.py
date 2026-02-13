#!/usr/bin/env python3
"""
YouTube Ranking Checker for Your Channels
Run this script locally to check which of your channels rank for your top keywords.

Usage: python check_rankings.py

Requirements: pip install requests
"""

import requests
import csv
import time
import json
from collections import defaultdict
from datetime import datetime

# ===========================================
# CONFIGURATION - UPDATE THESE
# ===========================================
SERPAPI_KEY = "72d5e93dbd8956798d692e1d03b8a912c4380a07902a99888942f45756a1d756"

# Your channel names to look for (case-insensitive matching)
YOUR_CHANNELS = [
    'security hero', 'securityhero',
    'cybersleuth', 'cyber sleuth', 'cyber_sleuth',
    'techroost', 'tech roost',
    'the opt out project', 'opt out project', 'optoutproject',
    'the pampered pup', 'pampered pup', 'pamperedpup',
    'the sniff test', 'sniff test', 'snifftest',
    'cozy crates', 'cozycrates',
]

# Top keywords to check (add/modify as needed)
TOP_KEYWORDS = [
    ("aura review", 470146),
    ("best identity theft protection", 361625),
    ("aura vs lifelock", 340656),
    ("spoton vs halo", 212002),
    ("spoton fence reviews", 151612),
    ("aura coupon code", 100600),
    ("halo collar reviews", 84660),
    ("nordvpn coupon code", 73881),
    ("lifelock review", 57280),
    ("best credit monitoring service", 54200),
    ("expressvpn coupon code", 53833),
    ("best wireless dog fence", 51057),
    ("aura vs bark", 46713),
    ("best gps dog fence", 43723),
    ("deleteme review", 39293),
    ("best parental control app for iphone", 38347),
    ("aura identity guard discount", 37600),
    ("best parental control apps", 35857),
    ("spoton coupon code", 30824),
    ("incogni review", 26544),
    ("how to remove your personal information from the internet", 25073),
    ("aura vs identity guard", 22600),
    ("best data recovery software", 21590),
    ("nordvpn review", 18064),
    ("halo collar promo code", 18995),
]

# ===========================================
# FUNCTIONS
# ===========================================

def check_youtube_ranking(keyword):
    """Check YouTube search results for a keyword"""
    try:
        url = "https://serpapi.com/search.json"
        params = {
            "engine": "youtube",
            "search_query": keyword,
            "api_key": SERPAPI_KEY
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            videos = data.get('video_results', [])

            results = {
                'keyword': keyword,
                'total_results': len(videos),
                'your_rankings': [],
                'top_10': []
            }

            for i, video in enumerate(videos[:10]):
                channel_name = video.get('channel', {}).get('name', '') or ''
                channel_lower = channel_name.lower()

                video_info = {
                    'position': i + 1,
                    'title': video.get('title', '')[:60],
                    'channel': channel_name,
                    'views': video.get('views', 'N/A'),
                    'is_yours': False
                }

                # Check if this is one of your channels
                for your_ch in YOUR_CHANNELS:
                    if your_ch in channel_lower:
                        video_info['is_yours'] = True
                        results['your_rankings'].append({
                            'position': i + 1,
                            'channel': channel_name,
                            'title': video.get('title', '')[:50],
                            'views': video.get('views', 'N/A')
                        })
                        break

                results['top_10'].append(video_info)

            return results
        else:
            return {'keyword': keyword, 'error': f"API error: {response.status_code}"}

    except Exception as e:
        return {'keyword': keyword, 'error': str(e)}


def main():
    print("="*100)
    print("YOUTUBE RANKING CHECK - Your Channels vs Competition")
    print("="*100)
    print(f"\nChecking {len(TOP_KEYWORDS)} keywords... (this may take a minute)\n")

    all_results = []
    your_rankings_summary = []
    not_ranking = []

    for i, (kw, rev) in enumerate(TOP_KEYWORDS):
        print(f"[{i+1}/{len(TOP_KEYWORDS)}] Checking: {kw[:50]}...", end=" ", flush=True)

        result = check_youtube_ranking(kw)
        all_results.append(result)

        if 'error' in result:
            print(f"ERROR: {result['error']}")
        elif result['your_rankings']:
            positions = [r['position'] for r in result['your_rankings']]
            channels = [r['channel'] for r in result['your_rankings']]
            print(f"✓ RANKING at position(s): {positions} ({', '.join(channels)})")
            your_rankings_summary.append({
                'keyword': kw,
                'revenue': rev,
                'positions': result['your_rankings'],
                'top_10': result['top_10']
            })
        else:
            print("✗ Not in top 10")
            not_ranking.append({
                'keyword': kw,
                'revenue': rev,
                'top_3': result['top_10'][:3] if result.get('top_10') else []
            })

        time.sleep(1)  # Rate limiting - be nice to the API

    # Summary
    print("\n\n" + "="*100)
    print("SUMMARY: YOUR CHANNEL RANKINGS")
    print("="*100)

    if your_rankings_summary:
        print(f"\n✅ RANKING FOR {len(your_rankings_summary)} / {len(TOP_KEYWORDS)} KEYWORDS:\n")
        print(f"{'Keyword':<45} {'Revenue':>12} {'Pos':>5} {'Channel':<25}")
        print("-"*95)

        for item in sorted(your_rankings_summary, key=lambda x: x['revenue'], reverse=True):
            for pos in item['positions']:
                print(f"{item['keyword'][:44]:<45} ${item['revenue']:>10,} #{pos['position']:>4} {pos['channel'][:24]:<25}")

    print("\n\n" + "="*100)
    print("❌ NOT RANKING (Top 10) - OPPORTUNITIES TO IMPROVE")
    print("="*100)

    if not_ranking:
        print(f"\nMissing from top 10 for {len(not_ranking)} keywords:\n")
        print(f"{'Keyword':<40} {'Revenue':>12} {'Who IS Ranking (Top 3)'}")
        print("-"*100)

        for item in sorted(not_ranking, key=lambda x: x['revenue'], reverse=True):
            top_channels = [v['channel'][:20] for v in item['top_3'] if v.get('channel')]
            print(f"{item['keyword'][:39]:<40} ${item['revenue']:>10,}  {', '.join(top_channels)}")

    # Save results to JSON
    output = {
        'timestamp': datetime.now().isoformat(),
        'ranking': your_rankings_summary,
        'not_ranking': not_ranking,
        'all_results': all_results
    }

    with open('ranking_results.json', 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n\nResults saved to ranking_results.json")

    # Print actionable insights
    print("\n\n" + "="*100)
    print("💡 ACTIONABLE INSIGHTS")
    print("="*100)

    if your_rankings_summary:
        total_ranking_rev = sum(item['revenue'] for item in your_rankings_summary)
        total_not_ranking_rev = sum(item['revenue'] for item in not_ranking)

        print(f"\n📊 Revenue from keywords you're ranking for: ${total_ranking_rev:,}")
        print(f"📊 Revenue from keywords you're NOT ranking for: ${total_not_ranking_rev:,}")
        print(f"📊 Potential upside if you ranked for all: ${total_not_ranking_rev:,}")

        # Top opportunities
        print("\n🎯 TOP 5 OPPORTUNITIES (highest revenue keywords you're not ranking for):")
        for item in sorted(not_ranking, key=lambda x: x['revenue'], reverse=True)[:5]:
            print(f"   • {item['keyword']} (${item['revenue']:,})")


if __name__ == "__main__":
    main()
