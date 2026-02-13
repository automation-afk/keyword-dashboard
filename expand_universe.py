#!/usr/bin/env python3
"""
Keyword Universe Expansion Script
==================================
Generates 17K+ keywords from brand × intent matrices, calculates revenue
potential, and inserts into Supabase keywords_master table via REST API.

Usage:
  python expand_universe.py                        # Generate all & insert
  python expand_universe.py --stats                # Show stats only
  python expand_universe.py --niche vpn            # Only one niche
  python expand_universe.py --enrich-youtube -n 50 # Enrich 50 keywords with SerpAPI
"""

import argparse
import json
import time
import urllib.request
import urllib.parse
import sys
from itertools import combinations

# ─── Configuration ────────────────────────────────────────────────────────────
SUPABASE_URL = 'https://nqleuhmuhsnkcvherbku.supabase.co'
SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5xbGV1aG11aHNua2N2aGVyYmt1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA4NTY4NTgsImV4cCI6MjA4NjQzMjg1OH0.fmToqAxwAyb_a5YA8zYAH6Y-B_hklgNHWmrq23JOVHA'
SERPAPI_KEY = '72d5e93dbd8956798d692e1d03b8a912c4380a07902a99888942f45756a1d756'
CURRENT_YEAR = '2026'

# ─── Brand Data ───────────────────────────────────────────────────────────────
UNIVERSE_BRANDS = {
    'vpn': [
        'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'protonvpn',
        'ipvanish', 'mullvad', 'pia', 'private internet access', 'windscribe',
        'tunnelbear', 'hotspot shield', 'atlas vpn', 'norton vpn',
        'kaspersky vpn', 'mozilla vpn', 'ivpn', 'airvpn', 'strongvpn',
        'vyprvpn', 'purevpn', 'hide my ass', 'bitdefender vpn',
        'avira vpn', 'zenmate'
    ],
    'home_security': [
        'simplisafe', 'ring', 'adt', 'vivint', 'frontpoint', 'cove',
        'abode', 'eufy', 'wyze', 'nest', 'arlo', 'guardian', 'brinks',
        'scout', 'link interactive', 'deep sentinel', 'kangaroo',
        'blue by adt', 'xfinity home', 'samsung smartthings'
    ],
    'web_hosting': [
        'bluehost', 'siteground', 'hostinger', 'dreamhost', 'a2 hosting',
        'inmotion', 'hostgator', 'godaddy', 'cloudways', 'wp engine',
        'kinsta', 'flywheel', 'namecheap', 'ionos', 'greengeeks',
        'fastcomet', 'scala hosting', 'liquid web', 'nexcess', 'pressable'
    ],
    'email_marketing': [
        'convertkit', 'mailchimp', 'activecampaign', 'aweber', 'getresponse',
        'mailerlite', 'drip', 'constant contact', 'brevo', 'sendinblue',
        'hubspot', 'klaviyo', 'campaign monitor', 'omnisend', 'moosend',
        'beehiiv', 'substack', 'buttondown', 'flodesk', 'kit'
    ],
    'identity_theft': [
        'lifelock', 'aura', 'identityforce', 'id watchdog', 'identity guard',
        'experian identityworks', 'mcafee identity', 'allstate identity',
        'credit karma', 'idshield', 'zander insurance', 'identityiq',
        'myfico', 'transunion', 'equifax'
    ],
    'data_broker_removal': [
        'deleteme', 'incogni', 'privacy duck', 'kanary', 'optery',
        'privacy bee', 'helloprivacy', 'onerep', 'removaly', 'brandyourself',
        'reputation defender', 'ez remove'
    ],
    'parental_control': [
        'bark', 'qustodio', 'net nanny', 'mspy', 'google family link',
        'kaspersky safe kids', 'norton family', 'circle', 'mobicip',
        'famisafe', 'ourpact', 'screen time', 'kidslox', 'eyezy',
        'mmguardian', 'securly', 'boomerang', 'familytime'
    ],
    'antivirus': [
        'norton', 'mcafee', 'bitdefender', 'kaspersky', 'avast', 'avg',
        'trend micro', 'eset', 'malwarebytes', 'webroot', 'windows defender',
        'avira', 'f-secure', 'sophos', 'totalav', 'pcprotect',
        'intego', 'vipre', 'k7 antivirus', 'zonealarm'
    ],
    'pet_insurance': [
        'lemonade', 'trupanion', 'pets best', 'aspca', 'embrace',
        'healthy paws', 'nationwide', 'fetch', 'figo', 'spot',
        'pawp', 'pumpkin', 'metlife', 'progressive', 'wagmo',
        'odie', 'bivvy', 'prudent pet', 'manypets'
    ],
    'gps_dog_fence': [
        'spoton', 'halo', 'fi collar', 'garmin', 'petsafe',
        'invisible fence', 'dogwatch', 'sportdog', 'tractive',
        'whistle', 'link aq', 'wagz', 'pawfit'
    ],
    'credit_repair': [
        'credit saint', 'lexington law', 'sky blue credit', 'the credit pros',
        'disputebee', 'self', 'credit strong', 'experian boost',
        'credit karma', 'ovation credit', 'creditrepair.com',
        'pinnacle credit repair', 'amc credit repair'
    ]
}

# Top brands per niche (for prioritizing comparisons and volume estimates)
TOP_BRANDS = {
    'vpn': ['nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'protonvpn'],
    'home_security': ['simplisafe', 'ring', 'adt', 'vivint', 'frontpoint'],
    'web_hosting': ['bluehost', 'siteground', 'hostinger', 'godaddy', 'wp engine'],
    'email_marketing': ['convertkit', 'mailchimp', 'activecampaign', 'hubspot', 'mailerlite'],
    'identity_theft': ['lifelock', 'aura', 'identity guard', 'identityforce', 'experian identityworks'],
    'data_broker_removal': ['deleteme', 'incogni', 'optery', 'kanary', 'privacy duck'],
    'parental_control': ['bark', 'qustodio', 'net nanny', 'mspy', 'google family link'],
    'antivirus': ['norton', 'mcafee', 'bitdefender', 'kaspersky', 'malwarebytes'],
    'pet_insurance': ['lemonade', 'trupanion', 'pets best', 'healthy paws', 'embrace'],
    'gps_dog_fence': ['spoton', 'halo', 'fi collar', 'petsafe', 'invisible fence'],
    'credit_repair': ['credit saint', 'lexington law', 'sky blue credit', 'the credit pros', 'disputebee']
}

BRAND_INTENTS = {
    'review': ['{brand} review', '{brand} review ' + CURRENT_YEAR, '{brand} reviews',
               '{brand} reviews reddit', 'is {brand} good', 'is {brand} legit',
               'is {brand} safe', 'is {brand} worth it'],
    'pricing': ['{brand} pricing', '{brand} cost', '{brand} plans',
                '{brand} price', 'how much is {brand}', 'how much does {brand} cost',
                '{brand} free trial', '{brand} money back guarantee',
                '{brand} student discount', '{brand} military discount'],
    'deal': ['{brand} coupon', '{brand} coupon code', '{brand} discount',
             '{brand} promo code', '{brand} deal', '{brand} sale',
             '{brand} black friday', '{brand} offer'],
    'comparison': ['{brand} vs {other}', '{brand} or {other}',
                   '{brand} compared to {other}', '{brand} versus {other}',
                   '{brand} vs {other} reddit'],
    'alternative': ['{brand} alternative', '{brand} alternatives',
                    'best {brand} alternative', 'sites like {brand}',
                    'apps like {brand}', '{brand} competitors'],
    'cancel': ['{brand} cancel', '{brand} cancel subscription',
               '{brand} refund', 'cancel {brand}', 'how to cancel {brand}'],
    'setup': ['how to use {brand}', 'how to set up {brand}',
              '{brand} tutorial', '{brand} setup guide', '{brand} download'],
    'problems': ['{brand} not working', '{brand} slow', '{brand} problems',
                 '{brand} issues', '{brand} complaints', '{brand} scam']
}

BEST_OF_USE_CASES = {
    'vpn': ['streaming', 'gaming', 'torrenting', 'china', 'netflix',
            'firestick', 'android', 'iphone', 'mac', 'windows', 'linux',
            'router', 'business', 'school', 'travel', 'privacy', 'speed',
            'cheap', 'free', 'families', 'uk', 'australia', 'canada',
            'chrome', 'firefox', 'kodi', 'roku', 'apple tv', 'ps5',
            'xbox', 'small business', 'remote work', 'japan',
            'india', 'dubai', 'turkey', 'russia', 'hulu', 'disney plus',
            'bbc iplayer', 'amazon prime', 'spotify'],
    'home_security': ['apartments', 'renters', 'no wifi', 'diy', 'no monthly fee',
                      'outdoor', 'indoor', 'pets', 'smart home', 'elderly',
                      'large property', 'rural areas', 'small business',
                      'garage', 'front door', 'backyard', 'night vision',
                      'wireless', 'wired', 'cheap', 'no contract',
                      'alexa', 'google home'],
    'web_hosting': ['wordpress', 'small business', 'ecommerce', 'blog',
                    'beginners', 'developers', 'agencies', 'speed',
                    'cheap', 'reseller', 'vps', 'dedicated', 'cloud',
                    'woocommerce', 'drupal', 'magento', 'node js',
                    'python', 'email hosting', 'high traffic'],
    'email_marketing': ['small business', 'beginners', 'ecommerce', 'bloggers',
                        'creators', 'nonprofits', 'agencies', 'automation',
                        'free', 'cheap', 'shopify', 'wordpress',
                        'deliverability', 'newsletters', 'course creators'],
    'identity_theft': ['families', 'seniors', 'children', 'business',
                       'cheap', 'free', 'credit monitoring', 'dark web monitoring',
                       'social security', 'tax fraud', 'medical identity theft'],
    'data_broker_removal': ['cheap', 'free', 'comprehensive', 'families',
                            'business', 'celebrities', 'real estate agents',
                            'doctors', 'lawyers', 'teachers'],
    'parental_control': ['iphone', 'android', 'chromebook', 'windows',
                         'mac', 'teens', 'toddlers', 'social media',
                         'youtube', 'gaming', 'wifi router', 'free',
                         'school', 'multiple devices', 'tiktok', 'snapchat',
                         'instagram', 'discord'],
    'antivirus': ['windows', 'mac', 'android', 'iphone', 'gaming',
                  'business', 'free', 'cheap', 'lightweight', 'speed',
                  'malware', 'ransomware', 'families', 'students',
                  'chromebook', 'linux', 'multiple devices'],
    'pet_insurance': ['dogs', 'cats', 'puppies', 'kittens', 'older dogs',
                      'older cats', 'pre existing conditions', 'cheap',
                      'large breeds', 'small breeds', 'exotic pets',
                      'multiple pets', 'hereditary conditions', 'wellness'],
    'gps_dog_fence': ['large dogs', 'small dogs', 'multiple dogs',
                      'large yards', 'acreage', 'no wifi', 'hilly terrain',
                      'rural', 'apartment', 'stubborn dogs', 'puppies'],
    'credit_repair': ['fast', 'cheap', 'free', 'beginners', 'mortgage',
                      'auto loan', 'collections', 'bankruptcy',
                      'student loans', 'medical debt']
}

PROBLEM_KEYWORDS = {
    'vpn': [
        'is my internet secure', 'can my isp see what i do',
        'how to hide ip address', 'how to unblock websites',
        'how to watch netflix from another country', 'how to bypass geo restrictions',
        'public wifi security', 'how to stop isp throttling',
        'how to torrent safely', 'vpn vs proxy', 'vpn vs tor',
        'do i need a vpn', 'what does a vpn do', 'how does a vpn work',
        'vpn for remote work', 'double vpn', 'kill switch vpn',
        'split tunneling vpn', 'vpn protocols explained', 'wireguard vs openvpn'
    ],
    'home_security': [
        'how to secure my home', 'home break in prevention',
        'package theft prevention', 'best doorbell camera',
        'best outdoor security camera', 'best indoor security camera',
        'security camera vs doorbell camera', 'smart lock vs deadbolt',
        'diy home security', 'home security without subscription',
        'how to install security cameras', 'security camera placement',
        'motion sensor lights', 'window sensors', 'glass break sensors',
        'security system monitoring', 'self monitored vs professional'
    ],
    'identity_theft': [
        'what to do if identity stolen', 'how to check if identity stolen',
        'someone opened account in my name', 'how to freeze credit',
        'how to check dark web for my info', 'social security number stolen',
        'credit card fraud what to do', 'phishing scam victim',
        'data breach notification what to do', 'child identity theft',
        'tax identity theft', 'medical identity theft', 'synthetic identity theft',
        'how to protect social security number', 'identity theft insurance worth it'
    ],
    'data_broker_removal': [
        'how to remove my info from google', 'how to remove yourself from spokeo',
        'how to remove yourself from whitepages', 'how to remove yourself from beenverified',
        'how to opt out of people search sites', 'how to remove mugshot from internet',
        'how to remove personal info from internet', 'right to be forgotten',
        'how to disappear from internet', 'people finder sites',
        'data brokers list', 'who has my personal data',
        'how to protect privacy online', 'doxxing prevention'
    ],
    'parental_control': [
        'how to monitor kids phone', 'how to block websites on kids phone',
        'how to set screen time limits', 'signs of cyberbullying',
        'how to talk to kids about online safety', 'age appropriate screen time',
        'how to monitor social media', 'parental controls on wifi router',
        'parental controls on youtube', 'kid safe search engine',
        'online predator warning signs', 'sexting prevention for parents',
        'gaming addiction in kids', 'how to monitor discord'
    ],
    'antivirus': [
        'how to tell if computer has virus', 'how to remove malware',
        'computer running slow virus', 'ransomware protection',
        'how to avoid phishing', 'free vs paid antivirus',
        'do i need antivirus for mac', 'antivirus vs internet security',
        'best firewall software', 'how to scan for viruses',
        'antivirus slowing down computer', 'real time protection vs scan'
    ],
    'pet_insurance': [
        'is pet insurance worth it', 'pet insurance vs savings account',
        'when to get pet insurance', 'pet insurance pre existing conditions',
        'how does pet insurance work', 'pet insurance deductible explained',
        'average vet bill cost', 'emergency vet cost',
        'most expensive dog breeds to insure', 'pet insurance waiting period',
        'pet insurance claim denied', 'wellness plan vs pet insurance'
    ],
    'gps_dog_fence': [
        'how to keep dog in yard without fence', 'invisible fence vs gps fence',
        'do gps dog fences work', 'are invisible fences cruel',
        'dog escapes invisible fence', 'how to train dog with invisible fence',
        'gps dog fence accuracy', 'gps collar vs buried wire fence',
        'best way to contain dog', 'dog fence for large property'
    ],
    'credit_repair': [
        'how to improve credit score fast', 'how to dispute credit report',
        'how to remove collections from credit report', 'credit score explained',
        'what is a good credit score', 'credit repair vs credit counseling',
        'how long does credit repair take', 'diy credit repair',
        'credit repair scams to avoid', 'pay for delete letter',
        'goodwill letter template', 'credit utilization explained'
    ],
    'web_hosting': [
        'shared vs vps vs dedicated hosting', 'how to choose web hosting',
        'website migration guide', 'hosting speed test',
        'ssl certificate explained', 'managed vs unmanaged hosting',
        'cloud hosting vs shared hosting', 'how to host a wordpress site',
        'web hosting uptime explained', 'cpanel vs plesk'
    ],
    'email_marketing': [
        'how to build email list', 'email marketing for beginners',
        'how to improve open rates', 'email deliverability tips',
        'email automation workflows', 'welcome email sequence',
        'email list segmentation', 'email marketing vs social media',
        'gdpr email marketing', 'email marketing roi'
    ]
}

# ─── Revenue Model Constants ─────────────────────────────────────────────────
EPV_BY_TYPE = {
    'deal': 1.18, 'comparison': 0.53, 'review': 0.31,
    'best_of': 0.16, 'informational': 0.31, 'pricing': 0.53,
    'alternative': 0.31, 'cancel': 0.05, 'setup': 0.05, 'problems': 0.10
}

CAPTURE_RATES = {
    'distributed': 0.15, 'top_heavy': 0.08,
    'winner_take_all': 0.03, 'no_data': 0.10
}

NICHE_MULTIPLIERS = {
    'vpn': 1.5, 'identity_theft': 1.4, 'data_broker_removal': 1.3,
    'antivirus': 1.2, 'web_hosting': 1.3, 'email_marketing': 1.2,
    'parental_control': 1.1, 'home_security': 1.0, 'pet_insurance': 1.0,
    'gps_dog_fence': 1.0, 'credit_repair': 1.2
}

NICHE_COMMISSIONS = {
    'vpn': 8.0, 'home_security': 15.0, 'web_hosting': 65.0,
    'email_marketing': 30.0, 'identity_theft': 10.0, 'data_broker_removal': 8.0,
    'parental_control': 6.0, 'antivirus': 8.0, 'pet_insurance': 12.0,
    'gps_dog_fence': 10.0, 'credit_repair': 15.0
}

# Niche labels for "best of" keywords
NICHE_LABELS = {
    'vpn': 'vpn', 'home_security': 'home security system',
    'web_hosting': 'web hosting', 'email_marketing': 'email marketing tool',
    'identity_theft': 'identity theft protection',
    'data_broker_removal': 'data removal service',
    'parental_control': 'parental control app', 'antivirus': 'antivirus',
    'pet_insurance': 'pet insurance', 'gps_dog_fence': 'gps dog fence',
    'credit_repair': 'credit repair service'
}

# Intent → metadata mappings
INTENT_FUNNEL = {
    'review': 'bofu', 'pricing': 'bofu', 'deal': 'bofu',
    'comparison': 'mofu', 'alternative': 'mofu', 'best_of': 'mofu',
    'cancel': 'tofu', 'setup': 'tofu', 'problems': 'tofu',
    'informational': 'tofu'
}

INTENT_BUYING = {
    'deal': 9, 'pricing': 8, 'review': 7, 'comparison': 7,
    'alternative': 6, 'best_of': 5, 'cancel': 2, 'setup': 3,
    'problems': 3, 'informational': 4
}

INTENT_CONVERSION = {
    'deal': 'high', 'pricing': 'high', 'review': 'medium',
    'comparison': 'high', 'alternative': 'medium', 'best_of': 'medium',
    'cancel': 'low', 'setup': 'low', 'problems': 'low',
    'informational': 'low'
}

INTENT_TIME_TO_CONVERT = {
    'deal': 'immediate', 'pricing': 'short', 'review': 'short',
    'comparison': 'short', 'alternative': 'medium', 'best_of': 'medium',
    'cancel': 'n/a', 'setup': 'n/a', 'problems': 'long',
    'informational': 'long'
}

INTENT_PROBLEM_TYPE = {
    'review': 'evaluation', 'pricing': 'comparison', 'deal': 'savings',
    'comparison': 'comparison', 'alternative': 'switching',
    'best_of': 'discovery', 'cancel': 'dissatisfaction',
    'setup': 'implementation', 'problems': 'troubleshooting',
    'informational': 'education'
}

INTENT_URGENCY = {
    'deal': 8, 'cancel': 7, 'problems': 7, 'pricing': 6,
    'review': 5, 'comparison': 5, 'alternative': 5, 'best_of': 4,
    'setup': 4, 'informational': 3
}

INTENT_CONTENT_ANGLE = {
    'review': 'In-depth review with pros, cons, and verdict',
    'pricing': 'Pricing breakdown with plan comparison table',
    'deal': f'Current deals and coupon codes for {CURRENT_YEAR}',
    'comparison': 'Side-by-side feature comparison with winner',
    'alternative': 'Top alternatives ranked with pros/cons',
    'best_of': 'Curated list with top picks and recommendations',
    'cancel': 'Step-by-step cancellation guide',
    'setup': 'Easy setup tutorial with screenshots',
    'problems': 'Troubleshooting guide with solutions',
    'informational': 'Comprehensive guide answering key questions'
}

# Base estimated volumes by intent type (monthly searches)
BASE_VOLUMES = {
    'review': 800, 'pricing': 400, 'deal': 600,
    'comparison': 250, 'alternative': 350, 'best_of': 900,
    'cancel': 150, 'setup': 200, 'problems': 150,
    'informational': 500
}


def estimate_volume(intent_type, niche, brand=None):
    """Estimate monthly search volume based on keyword characteristics."""
    base = BASE_VOLUMES.get(intent_type, 300)

    # Brand popularity multiplier
    brand_mult = 1.0
    if brand:
        top = TOP_BRANDS.get(niche, [])
        if brand in top[:2]:
            brand_mult = 2.5  # Top 2 brands get highest volume
        elif brand in top:
            brand_mult = 1.5  # Top 5 brands
        else:
            brand_mult = 0.5  # Smaller brands

    # Niche size multiplier (VPN/antivirus are bigger markets)
    niche_size = {
        'vpn': 1.8, 'antivirus': 1.5, 'web_hosting': 1.4,
        'home_security': 1.3, 'email_marketing': 1.2, 'pet_insurance': 1.1,
        'identity_theft': 1.0, 'parental_control': 0.9,
        'credit_repair': 0.9, 'data_broker_removal': 0.7,
        'gps_dog_fence': 0.5
    }
    size_mult = niche_size.get(niche, 1.0)

    return max(10, int(base * brand_mult * size_mult))


def calculate_revenue(volume, intent_type, niche, competition='medium'):
    """Calculate monthly revenue potential using the revenue model."""
    epv = EPV_BY_TYPE.get(intent_type, 0.17)
    niche_mult = NICHE_MULTIPLIERS.get(niche, 1.0)

    # Capture rate based on competition
    comp_map = {'low': 'distributed', 'medium': 'top_heavy', 'high': 'winner_take_all'}
    pattern = comp_map.get(competition, 'no_data')
    capture = CAPTURE_RATES.get(pattern, 0.10)

    willingness = 1.0  # Default willingness multiplier
    revenue = volume * capture * epv * niche_mult * willingness
    return round(revenue, 2)


def estimate_competition(intent_type, brand=None, niche=None):
    """Estimate competition level for a keyword."""
    top = TOP_BRANDS.get(niche, []) if niche else []

    if intent_type == 'deal':
        return 'high' if brand in top[:3] else 'medium'
    elif intent_type in ('review', 'comparison'):
        return 'high' if brand in top[:2] else 'medium'
    elif intent_type == 'best_of':
        return 'high'
    elif intent_type in ('pricing', 'alternative'):
        return 'medium'
    elif intent_type in ('cancel', 'setup', 'problems'):
        return 'low'
    elif intent_type == 'informational':
        return 'medium'
    return 'medium'


def tier_from_revenue(revenue):
    """Assign opportunity tier based on revenue potential."""
    if revenue >= 250:
        return 'S'
    elif revenue >= 100:
        return 'A'
    elif revenue >= 50:
        return 'B'
    elif revenue >= 20:
        return 'C'
    else:
        return 'D'


def priority_score(revenue, buying_intent, urgency, competition):
    """Calculate a 0-100 priority score."""
    # Revenue component (0-40)
    rev_score = min(40, revenue / 10)

    # Buying intent component (0-30)
    intent_score = buying_intent * 3.33

    # Urgency component (0-15)
    urg_score = urgency * 1.5

    # Competition penalty (0-15 penalty for high competition)
    comp_penalty = {'low': 0, 'medium': 5, 'high': 12}.get(competition, 5)

    score = rev_score + intent_score + urg_score - comp_penalty
    return round(max(0, min(100, score)), 1)


def generate_rationale(intent_type, brand=None, niche=None, use_case=None):
    """Generate a brief rationale for why this keyword matters."""
    niche_label = NICHE_LABELS.get(niche, niche or '').replace('_', ' ')

    if intent_type == 'review':
        return f'High-intent review keyword - searchers evaluating {brand} before purchase'
    elif intent_type == 'pricing':
        return f'Pricing keyword signals active purchase consideration for {brand}'
    elif intent_type == 'deal':
        return f'Deal/coupon keyword - highest conversion intent, searcher ready to buy {brand}'
    elif intent_type == 'comparison':
        return f'Comparison keyword - searcher deciding between options, strong buying signal'
    elif intent_type == 'alternative':
        return f'Alternative keyword - searcher unhappy with {brand} or exploring options'
    elif intent_type == 'best_of':
        return f'Best-of keyword for {use_case or niche_label} - broad audience, list content'
    elif intent_type == 'cancel':
        return f'Cancellation keyword - opportunity to present alternatives to {brand}'
    elif intent_type == 'setup':
        return f'Setup/tutorial keyword - post-purchase, builds authority and trust'
    elif intent_type == 'problems':
        return f'Problem keyword - opportunity to present {brand} alternatives as solutions'
    elif intent_type == 'informational':
        return f'Informational keyword - builds authority in {niche_label} space'
    return f'{intent_type} keyword for {niche_label}'


# ─── Keyword Generation ──────────────────────────────────────────────────────
def generate_all_keywords(niche_filter=None):
    """Generate the full keyword universe."""
    seen = set()
    keywords = []

    niches = [niche_filter] if niche_filter else list(UNIVERSE_BRANDS.keys())

    for niche in niches:
        brands = UNIVERSE_BRANDS.get(niche, [])
        if not brands:
            continue

        # ── 1. Brand + Intent keywords (non-comparison) ──
        for brand in brands:
            for intent_type, templates in BRAND_INTENTS.items():
                if intent_type == 'comparison':
                    continue  # Handle separately

                for template in templates:
                    kw = template.format(brand=brand).lower().strip()
                    if kw in seen:
                        continue
                    seen.add(kw)

                    vol = estimate_volume(intent_type, niche, brand)
                    comp = estimate_competition(intent_type, brand, niche)
                    rev = calculate_revenue(vol, intent_type, niche, comp)
                    bi = INTENT_BUYING.get(intent_type, 5)
                    urg = INTENT_URGENCY.get(intent_type, 5)
                    ps = priority_score(rev, bi, urg, comp)

                    keywords.append({
                        'keyword': kw,
                        'niche': niche,
                        'funnel': INTENT_FUNNEL.get(intent_type, 'mofu'),
                        'intent_type': intent_type,
                        'volume': vol,
                        'commission': NICHE_COMMISSIONS.get(niche, 10.0),
                        'revenue_potential': rev,
                        'buying_intent': bi,
                        'yt_avg_monthly_views': 0,
                        'yt_view_pattern': 'no_data',
                        'priority_score': ps,
                        'opportunity_tier': tier_from_revenue(rev),
                        'competition': comp,
                        'content_angle': INTENT_CONTENT_ANGLE.get(intent_type, ''),
                        'rationale': generate_rationale(intent_type, brand, niche),
                        'conversion_likelihood': INTENT_CONVERSION.get(intent_type, 'medium'),
                        'time_to_convert': INTENT_TIME_TO_CONVERT.get(intent_type, 'medium'),
                        'problem_type': INTENT_PROBLEM_TYPE.get(intent_type, 'general'),
                        'urgency_score': urg,
                        'yt_top_video_title': '',
                        'yt_top_video_views': 0,
                        'yt_top_video_channel': '',
                        'added_by_email': 'system',
                        'added_by_name': 'Universe Generator',
                        'source': 'universe'
                    })

        # ── 2. Comparison keywords (brand vs brand) ──
        comparison_templates = BRAND_INTENTS['comparison']
        for brand_a, brand_b in combinations(brands, 2):
            for template in comparison_templates:
                kw = template.format(brand=brand_a, other=brand_b).lower().strip()
                if kw in seen:
                    continue
                seen.add(kw)

                # Use the more popular brand for volume estimation
                top = TOP_BRANDS.get(niche, [])
                primary_brand = brand_a if brand_a in top else brand_b
                is_top_matchup = brand_a in top[:5] and brand_b in top[:5]

                vol = estimate_volume('comparison', niche, primary_brand)
                if is_top_matchup:
                    vol = int(vol * 1.5)  # Top vs top gets more searches

                comp = 'high' if is_top_matchup else 'medium'
                rev = calculate_revenue(vol, 'comparison', niche, comp)
                bi = INTENT_BUYING['comparison']
                urg = INTENT_URGENCY['comparison']
                ps = priority_score(rev, bi, urg, comp)

                keywords.append({
                    'keyword': kw,
                    'niche': niche,
                    'funnel': 'mofu',
                    'intent_type': 'comparison',
                    'volume': vol,
                    'commission': NICHE_COMMISSIONS.get(niche, 10.0),
                    'revenue_potential': rev,
                    'buying_intent': bi,
                    'yt_avg_monthly_views': 0,
                    'yt_view_pattern': 'no_data',
                    'priority_score': ps,
                    'opportunity_tier': tier_from_revenue(rev),
                    'competition': comp,
                    'content_angle': 'Side-by-side feature comparison with winner',
                    'rationale': f'Comparison: {brand_a} vs {brand_b} - strong buying signal',
                    'conversion_likelihood': 'high',
                    'time_to_convert': 'short',
                    'problem_type': 'comparison',
                    'urgency_score': urg,
                    'yt_top_video_title': '',
                    'yt_top_video_views': 0,
                    'yt_top_video_channel': '',
                    'added_by_email': 'system',
                    'added_by_name': 'Universe Generator',
                    'source': 'universe'
                })

        # ── 3. Best-of keywords ──
        niche_label = NICHE_LABELS.get(niche, niche.replace('_', ' '))
        use_cases = BEST_OF_USE_CASES.get(niche, [])

        # Standalone "best [niche]" keywords
        for suffix in ['', f' {CURRENT_YEAR}', ' reddit']:
            kw = f'best {niche_label}{suffix}'.lower().strip()
            if kw in seen:
                continue
            seen.add(kw)

            vol = estimate_volume('best_of', niche) * 2  # Standalone gets more volume
            comp = 'high'
            rev = calculate_revenue(vol, 'best_of', niche, comp)
            bi = INTENT_BUYING['best_of']
            urg = INTENT_URGENCY['best_of']
            ps = priority_score(rev, bi, urg, comp)

            keywords.append({
                'keyword': kw, 'niche': niche, 'funnel': 'mofu',
                'intent_type': 'best_of', 'volume': vol,
                'commission': NICHE_COMMISSIONS.get(niche, 10.0),
                'revenue_potential': rev, 'buying_intent': bi,
                'yt_avg_monthly_views': 0, 'yt_view_pattern': 'no_data',
                'priority_score': ps, 'opportunity_tier': tier_from_revenue(rev),
                'competition': comp,
                'content_angle': f'Definitive {CURRENT_YEAR} list of top {niche_label} options',
                'rationale': f'Head term for {niche_label} - highest volume best-of keyword',
                'conversion_likelihood': 'medium', 'time_to_convert': 'medium',
                'problem_type': 'discovery', 'urgency_score': urg,
                'yt_top_video_title': '', 'yt_top_video_views': 0,
                'yt_top_video_channel': '',
                'added_by_email': 'system', 'added_by_name': 'Universe Generator',
                'source': 'universe'
            })

        # "best [niche] for [use case]" keywords
        for use_case in use_cases:
            for suffix in ['', f' {CURRENT_YEAR}']:
                kw = f'best {niche_label} for {use_case}{suffix}'.lower().strip()
                if kw in seen:
                    continue
                seen.add(kw)

                vol = estimate_volume('best_of', niche)
                comp = estimate_competition('best_of', niche=niche)
                rev = calculate_revenue(vol, 'best_of', niche, comp)
                bi = INTENT_BUYING['best_of']
                urg = INTENT_URGENCY['best_of']
                ps = priority_score(rev, bi, urg, comp)

                keywords.append({
                    'keyword': kw, 'niche': niche, 'funnel': 'mofu',
                    'intent_type': 'best_of', 'volume': vol,
                    'commission': NICHE_COMMISSIONS.get(niche, 10.0),
                    'revenue_potential': rev, 'buying_intent': bi,
                    'yt_avg_monthly_views': 0, 'yt_view_pattern': 'no_data',
                    'priority_score': ps, 'opportunity_tier': tier_from_revenue(rev),
                    'competition': comp,
                    'content_angle': f'Best {niche_label} for {use_case} - curated recommendations',
                    'rationale': generate_rationale('best_of', niche=niche, use_case=use_case),
                    'conversion_likelihood': 'medium', 'time_to_convert': 'medium',
                    'problem_type': 'discovery', 'urgency_score': urg,
                    'yt_top_video_title': '', 'yt_top_video_views': 0,
                    'yt_top_video_channel': '',
                    'added_by_email': 'system', 'added_by_name': 'Universe Generator',
                    'source': 'universe'
                })

        # ── 4. Problem / Informational keywords ──
        problems = PROBLEM_KEYWORDS.get(niche, [])
        for problem in problems:
            kw = problem.lower().strip()
            if kw in seen:
                continue
            seen.add(kw)

            vol = estimate_volume('informational', niche)
            comp = estimate_competition('informational', niche=niche)
            rev = calculate_revenue(vol, 'informational', niche, comp)
            bi = INTENT_BUYING['informational']
            urg = INTENT_URGENCY['informational']
            ps = priority_score(rev, bi, urg, comp)

            keywords.append({
                'keyword': kw, 'niche': niche, 'funnel': 'tofu',
                'intent_type': 'informational', 'volume': vol,
                'commission': NICHE_COMMISSIONS.get(niche, 10.0),
                'revenue_potential': rev, 'buying_intent': bi,
                'yt_avg_monthly_views': 0, 'yt_view_pattern': 'no_data',
                'priority_score': ps, 'opportunity_tier': tier_from_revenue(rev),
                'competition': comp,
                'content_angle': 'Comprehensive guide answering key questions',
                'rationale': generate_rationale('informational', niche=niche),
                'conversion_likelihood': 'low', 'time_to_convert': 'long',
                'problem_type': 'education', 'urgency_score': urg,
                'yt_top_video_title': '', 'yt_top_video_views': 0,
                'yt_top_video_channel': '',
                'added_by_email': 'system', 'added_by_name': 'Universe Generator',
                'source': 'universe'
            })

    return keywords


# ─── Supabase REST API ────────────────────────────────────────────────────────
def supabase_request(method, path, data=None, params=None):
    """Make a request to Supabase REST API."""
    url = f'{SUPABASE_URL}/rest/v1/{path}'
    if params:
        url += '?' + urllib.parse.urlencode(params)

    body = json.dumps(data).encode('utf-8') if data else None
    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}',
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates'
    }

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode('utf-8')
            return resp.status, resp_body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return 0, str(e)


def clear_universe_keywords():
    """Delete all universe-generated keywords from keywords_master."""
    # Delete keywords with source='universe'
    url = f'{SUPABASE_URL}/rest/v1/keywords_master?source=eq.universe'
    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}',
        'Content-Type': 'application/json'
    }
    req = urllib.request.Request(url, headers=headers, method='DELETE')
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        print(f'  Error clearing: {e}')
        return 0


def insert_keywords(keywords, batch_size=100):
    """Insert keywords into Supabase keywords_master via REST API."""
    total = len(keywords)
    inserted = 0
    errors = 0

    for i in range(0, total, batch_size):
        batch = keywords[i:i+batch_size]
        status, body = supabase_request('POST', 'keywords_master', batch)

        if status in (200, 201):
            inserted += len(batch)
        else:
            # Try individually on batch failure
            for kw in batch:
                s, b = supabase_request('POST', 'keywords_master', [kw])
                if s in (200, 201):
                    inserted += 1
                else:
                    errors += 1

        pct = int((i + len(batch)) / total * 100)
        sys.stdout.write(f'\r  Inserting: {inserted}/{total} ({pct}%) | Errors: {errors}')
        sys.stdout.flush()

        # Small delay to avoid rate limiting
        if i + batch_size < total:
            time.sleep(0.1)

    print()  # Newline after progress
    return inserted, errors


# ─── SerpAPI YouTube Enrichment ───────────────────────────────────────────────
def serpapi_youtube_search(keyword):
    """Search YouTube via SerpAPI for a keyword. Returns enrichment data."""
    params = urllib.parse.urlencode({
        'engine': 'youtube',
        'search_query': keyword,
        'api_key': SERPAPI_KEY
    })
    url = f'https://serpapi.com/search.json?{params}'

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return None

    results = data.get('video_results', [])
    if not results:
        return {'yt_avg_monthly_views': 0, 'yt_view_pattern': 'no_data',
                'yt_top_video_title': '', 'yt_top_video_views': 0,
                'yt_top_video_channel': '', 'yt_video_count': 0}

    views = []
    top_video = results[0]
    for v in results[:10]:
        view_count = v.get('views', 0)
        if isinstance(view_count, str):
            view_count = int(''.join(c for c in view_count if c.isdigit()) or '0')
        views.append(view_count)

    total_views = sum(views)
    avg_views = total_views // max(len(views), 1)

    # Determine view pattern
    if views and max(views) > 0:
        top_share = views[0] / max(total_views, 1)
        if top_share > 0.6:
            pattern = 'winner_take_all'
        elif top_share > 0.3:
            pattern = 'top_heavy'
        else:
            pattern = 'distributed'
    else:
        pattern = 'no_data'

    top_views = views[0] if views else 0
    top_title = top_video.get('title', '')[:200]
    top_channel = (top_video.get('channel', {}).get('name', '') or
                   top_video.get('channel_name', ''))[:100]

    return {
        'yt_avg_monthly_views': avg_views,
        'yt_view_pattern': pattern,
        'yt_top_video_title': top_title,
        'yt_top_video_views': top_views,
        'yt_top_video_channel': top_channel,
        'yt_video_count': len(results)
    }


def enrich_with_youtube(limit=50):
    """Enrich keywords that don't have YouTube data yet."""
    # Fetch keywords without YT data
    params = {
        'yt_view_pattern': 'eq.no_data',
        'select': 'keyword',
        'limit': str(limit),
        'order': 'priority_score.desc'
    }
    status, body = supabase_request('GET', 'keywords_master', params=params)

    if status != 200:
        print(f'  Error fetching keywords: {body}')
        return

    keywords_to_enrich = json.loads(body)
    if not keywords_to_enrich:
        print('  No keywords need YouTube enrichment')
        return

    print(f'  Enriching {len(keywords_to_enrich)} keywords with YouTube data...')
    enriched = 0

    for i, row in enumerate(keywords_to_enrich):
        kw = row['keyword']
        print(f'  [{i+1}/{len(keywords_to_enrich)}] {kw}...', end=' ')

        yt_data = serpapi_youtube_search(kw)
        if yt_data:
            # Update via REST API
            update_url = f'keywords_master?keyword=eq.{urllib.parse.quote(kw)}'
            status, _ = supabase_request('PATCH', update_url, yt_data)
            if status in (200, 204):
                enriched += 1
                print(f'OK ({yt_data["yt_avg_monthly_views"]} avg views)')
            else:
                print(f'Update failed ({status})')
        else:
            print('API error')

        # Rate limit: 1 request per second
        time.sleep(1.2)

    print(f'\n  Enriched {enriched}/{len(keywords_to_enrich)} keywords')


# ─── Statistics ───────────────────────────────────────────────────────────────
def show_stats(keywords):
    """Show statistics about the generated keyword universe."""
    by_niche = {}
    by_intent = {}
    by_tier = {}
    by_funnel = {}
    total_rev = 0

    for kw in keywords:
        niche = kw['niche']
        intent = kw['intent_type']
        tier = kw['opportunity_tier']
        funnel = kw['funnel']

        by_niche[niche] = by_niche.get(niche, 0) + 1
        by_intent[intent] = by_intent.get(intent, 0) + 1
        by_tier[tier] = by_tier.get(tier, 0) + 1
        by_funnel[funnel] = by_funnel.get(funnel, 0) + 1
        total_rev += kw['revenue_potential']

    print('\n' + '='*60)
    print(f'  KEYWORD UNIVERSE STATISTICS')
    print(f'  Total keywords: {len(keywords):,}')
    print(f'  Total est. monthly revenue potential: ${total_rev:,.0f}')
    print('='*60)

    print('\n  BY NICHE:')
    for niche, count in sorted(by_niche.items(), key=lambda x: -x[1]):
        print(f'    {niche:<25} {count:>6,}')

    print('\n  BY INTENT TYPE:')
    for intent, count in sorted(by_intent.items(), key=lambda x: -x[1]):
        print(f'    {intent:<25} {count:>6,}')

    print('\n  BY OPPORTUNITY TIER:')
    for tier in ['S', 'A', 'B', 'C', 'D']:
        count = by_tier.get(tier, 0)
        print(f'    Tier {tier:<22} {count:>6,}')

    print('\n  BY FUNNEL STAGE:')
    for funnel, count in sorted(by_funnel.items(), key=lambda x: -x[1]):
        print(f'    {funnel:<25} {count:>6,}')

    # Top 20 by revenue
    top = sorted(keywords, key=lambda x: -x['revenue_potential'])[:20]
    print('\n  TOP 20 KEYWORDS BY REVENUE POTENTIAL:')
    for i, kw in enumerate(top, 1):
        print(f'    {i:>2}. ${kw["revenue_potential"]:>7.2f}/mo  {kw["keyword"][:50]}')

    print()


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Keyword Universe Expansion')
    parser.add_argument('--stats', action='store_true', help='Show stats only, no insert')
    parser.add_argument('--niche', type=str, help='Generate for a single niche only')
    parser.add_argument('--enrich-youtube', action='store_true', help='Enrich with SerpAPI YouTube data')
    parser.add_argument('-n', '--limit', type=int, default=50, help='Number of keywords to enrich')
    parser.add_argument('--no-clear', action='store_true', help='Skip clearing existing universe keywords')
    args = parser.parse_args()

    if args.enrich_youtube:
        print('[ENRICH] Starting YouTube data enrichment via SerpAPI...')
        enrich_with_youtube(limit=args.limit)
        return

    print('[STEP 1] Generating keyword universe...')
    keywords = generate_all_keywords(niche_filter=args.niche)
    print(f'  Generated {len(keywords):,} unique keywords')

    show_stats(keywords)

    if args.stats:
        return

    if not args.no_clear:
        print('[STEP 2] Clearing existing universe keywords...')
        status = clear_universe_keywords()
        print(f'  Clear status: {status}')

    print('[STEP 3] Inserting into Supabase...')
    inserted, errors = insert_keywords(keywords)
    print(f'  Done! Inserted: {inserted:,} | Errors: {errors}')

    # Verify count
    status, body = supabase_request('GET', 'keywords_master',
                                     params={'select': 'keyword', 'limit': '1'})
    if status == 200:
        # Get total count with HEAD request
        count_url = f'{SUPABASE_URL}/rest/v1/keywords_master?select=keyword'
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {SUPABASE_KEY}',
            'Prefer': 'count=exact',
            'Range-Unit': 'items',
            'Range': '0-0'
        }
        req = urllib.request.Request(count_url, headers=headers, method='GET')
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                content_range = resp.headers.get('Content-Range', '')
                if '/' in content_range:
                    total = content_range.split('/')[-1]
                    print(f'\n  Total keywords in Supabase: {total}')
        except Exception:
            pass

    print('\n[DONE] Keyword universe expansion complete!')
    print('  - Keywords have estimated volumes (replace with real data via Keywords Everywhere/DataForSEO)')
    print('  - Run with --enrich-youtube to add YouTube data from SerpAPI')


if __name__ == '__main__':
    main()
