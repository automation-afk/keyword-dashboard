from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, session
try:
    import anthropic
except ImportError:
    anthropic = None
    print("[WARN] anthropic package not installed - chatbot AI will be unavailable")
import csv
import json
import os
import requests
import base64
import time
import urllib.request
from datetime import datetime
import psycopg2
import psycopg2.extras
from functools import wraps
import gzip
import io
import hashlib
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# Fix for running behind Railway's proxy - ensures correct URL generation
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ============================================
# SESSION & SECURITY CONFIG
# ============================================
_secret = os.environ.get('FLASK_SECRET_KEY', 'wU8LYRC3xWgwRe3xBnmrg8z5kP2mQ7v')
print(f"[CONFIG] Secret key loaded: {_secret[:6]}... (len={len(_secret)})")
app.secret_key = _secret
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable static file caching

@app.after_request
def add_no_cache_headers(response):
    if 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


# ============================================
# GZIP COMPRESSION
# ============================================
@app.after_request
def gzip_response(response):
    """Compress JSON responses with gzip (70-80% size reduction)."""
    if response.status_code < 200 or response.status_code >= 300:
        return response
    if 'gzip' not in request.headers.get('Accept-Encoding', ''):
        return response
    if response.content_length is not None and response.content_length < 500:
        return response
    if 'application/json' not in response.content_type:
        return response

    gzip_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gzip_buf, mode='wb', compresslevel=6) as gz:
        gz.write(response.get_data())
    response.set_data(gzip_buf.getvalue())
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(response.get_data())
    return response


# ============================================
# IN-MEMORY RESPONSE CACHE
# ============================================
_response_cache = {}  # {key: {data: ..., expires: timestamp}}

def cache_response(cache_key, ttl_seconds=300):
    """Decorator to cache endpoint responses in memory."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            now = time.time()
            # Check if ?refresh=true to bust cache
            refresh = request.args.get('refresh', '').lower() == 'true'
            cached = _response_cache.get(cache_key)
            if cached and not refresh and cached['expires'] > now:
                return cached['data']
            result = f(*args, **kwargs)
            _response_cache[cache_key] = {'data': result, 'expires': now + ttl_seconds}
            return result
        return wrapper
    return decorator

def invalidate_cache(*keys):
    """Clear specific cache keys (call after data changes)."""
    for k in keys:
        _response_cache.pop(k, None)

# ============================================
# GOOGLE OAUTH CONFIG
# ============================================
# Set these in Railway environment variables:
# GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, ALLOWED_DOMAINS

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    },
    authorize_params={
        'prompt': 'select_account',
        'access_type': 'offline'
    }
)

# Allowed email domains (comma-separated in env var)
# Example: ALLOWED_DOMAINS=mycompany.com,partner.com
_raw_domains = os.environ.get('ALLOWED_DOMAINS', '').strip('"\'')  # Strip quotes if accidentally included
ALLOWED_DOMAINS = [d.strip().lower().strip('"\'') for d in _raw_domains.split(',') if d.strip()]
print(f"[AUTH] Allowed domains: {ALLOWED_DOMAINS}")

# ============================================
# AUTH HELPERS
# ============================================
def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip auth if no OAuth configured (for local dev)
        if not os.environ.get('GOOGLE_CLIENT_ID'):
            return f(*args, **kwargs)

        if 'user' not in session:
            # For API routes, return 401
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            # For page routes, redirect to login
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_domain_allowed(email):
    """Check if email domain is in allowed list"""
    if not ALLOWED_DOMAINS:
        print(f"[AUTH] No domain restrictions configured, allowing all")
        return True  # No restrictions if not configured
    domain = email.split('@')[-1].lower().strip()
    allowed = domain in ALLOWED_DOMAINS
    print(f"[AUTH] Checking domain '{domain}' against {ALLOWED_DOMAINS} -> {'ALLOWED' if allowed else 'DENIED'}")
    return allowed

def get_current_user():
    """Get current logged-in user info"""
    return session.get('user', None)

# ============================================
# AUTH ROUTES
# ============================================
@app.route('/login')
def login():
    """Initiate Google OAuth login"""
    if not os.environ.get('GOOGLE_CLIENT_ID'):
        # No OAuth configured, auto-login for dev
        return redirect(url_for('index'))

    # Use explicit APP_URL if set, otherwise generate from request
    app_url = os.environ.get('APP_URL', '').rstrip('/')
    if app_url:
        redirect_uri = f"{app_url}/auth/callback"
    else:
        redirect_uri = url_for('auth_callback', _external=True)

    print(f"[AUTH] APP_URL={app_url}")
    print(f"[AUTH] redirect_uri={redirect_uri}")
    print(f"[AUTH] request.url={request.url}")
    print(f"[AUTH] request.host={request.host}")
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    """Handle Google OAuth callback"""
    try:
        print(f"[AUTH] Processing OAuth callback...")
        print(f"[AUTH] callback request.url={request.url}")
        print(f"[AUTH] callback request.host={request.host}")
        print(f"[AUTH] session keys={list(session.keys())}")

        # Try normal token exchange first
        try:
            token = google.authorize_access_token()
        except Exception as csrf_err:
            print(f"[AUTH] State check failed: {csrf_err}, attempting manual token exchange")
            # Manual token exchange bypassing state check
            import requests as req
            code = request.args.get('code')
            app_url = os.environ.get('APP_URL', '').rstrip('/')
            redirect_uri = f"{app_url}/auth/callback" if app_url else url_for('auth_callback', _external=True)
            token_resp = req.post('https://oauth2.googleapis.com/token', data={
                'code': code,
                'client_id': os.environ.get('GOOGLE_CLIENT_ID'),
                'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET'),
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            })
            token = token_resp.json()
            if 'error' in token:
                raise Exception(f"Token exchange failed: {token}")

        # Get user info from ID token or userinfo endpoint
        user_info = token.get('userinfo')
        if not user_info:
            if 'id_token' in token:
                import json, base64
                # Decode JWT payload (middle part)
                payload = token['id_token'].split('.')[1]
                payload += '=' * (4 - len(payload) % 4)  # pad base64
                user_info = json.loads(base64.urlsafe_b64decode(payload))
            else:
                print("[AUTH] Fetching user info from Google...")
                import requests as req
                resp = req.get('https://openidconnect.googleapis.com/v1/userinfo',
                    headers={'Authorization': f"Bearer {token.get('access_token')}"})
                user_info = resp.json()

        email = user_info.get('email', '')
        print(f"[AUTH] User attempting login: {email}")

        # Check domain restriction
        if not is_domain_allowed(email):
            print(f"[AUTH] ACCESS DENIED for {email}")
            return render_template('unauthorized.html',
                email=email,
                allowed_domains=ALLOWED_DOMAINS
            ), 403

        print(f"[AUTH] ACCESS GRANTED for {email}")

        # Store user in session
        session['user'] = {
            'email': email,
            'name': user_info.get('name', ''),
            'picture': user_info.get('picture', '')
        }

        return redirect(url_for('index'))

    except Exception as e:
        import traceback
        print(f"[AUTH] ERROR during authentication: {str(e)}")
        print(f"[AUTH] Traceback: {traceback.format_exc()}")
        return f"Authentication error: {str(e)}", 500

@app.route('/logout')
def logout():
    """Log out user"""
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/api/auth/user')
def get_user():
    """Get current user info for frontend"""
    user = get_current_user()
    if user:
        return jsonify({'authenticated': True, 'user': user})
    return jsonify({'authenticated': False})

# ============================================
# API KEYS (set via environment variables in production)
# ============================================
AHREFS_API_KEY = os.environ.get('AHREFS_API_KEY', '').strip()
KEYWORDS_EVERYWHERE_API_KEY = os.environ.get('KEYWORDS_EVERYWHERE_API_KEY', '').strip()
SERPAPI_API_KEY = os.environ.get('SERPAPI_API_KEY', '72d5e93dbd8956798d692e1d03b8a912c4380a07902a99888942f45756a1d756').strip()
DATAFORSEO_LOGIN = os.environ.get('DATAFORSEO_LOGIN', '').strip()
DATAFORSEO_PASSWORD = os.environ.get('DATAFORSEO_PASSWORD', '').strip()
YOUTUBE_API_KEY = os.environ.get('YOUTUBE_API_KEY', '').strip()  # For comprehensive channel video fetching

# Log API key status on startup (without revealing the actual key)
print(f"Keywords Everywhere API key configured: {bool(KEYWORDS_EVERYWHERE_API_KEY)} (length: {len(KEYWORDS_EVERYWHERE_API_KEY)})")
print(f"DataForSEO configured: {bool(DATAFORSEO_LOGIN and DATAFORSEO_PASSWORD)}")
print(f"YouTube Data API key configured: {bool(YOUTUBE_API_KEY)}")

# ============================================
# BIGQUERY CLIENT (YouTube SERP data source)
# ============================================
BQ_PROJECT_ID = "company-wide-370010"
BQ_SERP_TABLE = "`company-wide-370010.1_YT_Serp_result.ALL_Time YT Serp`"
BQ_METRICS_TABLE = "`company-wide-370010.Digibot.Metrics_by_Month`"
BQ_DAILY_REV_TABLE = "`company-wide-370010.Digibot.Daily_Rev_Metrics_by_Video_ID`"
BQ_GENERAL_INFO_TABLE = "`company-wide-370010.Digibot.Digibot_General_info`"

_bq_client = None

def get_bq_client():
    """Lazy-init BigQuery client from service account JSON."""
    global _bq_client
    if _bq_client is not None:
        return _bq_client

    sa_json = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON', '')
    if not sa_json:
        print("[BQ] WARNING: GOOGLE_SERVICE_ACCOUNT_JSON not set")
        return None

    try:
        from google.cloud import bigquery
        from google.oauth2.service_account import Credentials

        if sa_json.strip().startswith('{'):
            info = json.loads(sa_json)
            creds = Credentials.from_service_account_info(info)
        else:
            creds = Credentials.from_service_account_file(sa_json)

        _bq_client = bigquery.Client(credentials=creds, project=BQ_PROJECT_ID)
        print("[BQ] BigQuery client initialized successfully")
        return _bq_client
    except Exception as e:
        print(f"[BQ] Error initializing BigQuery client: {e}")
        return None

# ============================================
# DIGIDOM CHANNEL REGISTRY (single source of truth)
# ============================================
DIGIDOM_CHANNELS = {
    'SH': {
        'bq_names': ['Home Security Heroes'],
        'match_patterns': ['security hero', 'securityhero', 'home security heroes'],
    },
    'CS': {
        'bq_names': ['Cyber Sleuth'],
        'match_patterns': ['cybersleuth', 'cyber sleuth', 'cyber_sleuth'],
    },
    'TR': {
        'bq_names': ['The Tech Roost'],
        'match_patterns': ['the tech roost', 'tech roost'],
    },
    'TOOP': {
        'bq_names': ['The Opt Out Project'],
        'match_patterns': ['opt out project', 'optoutproject', 'the opt out'],
    },
    'TPP': {
        'bq_names': ['The Pampered Pup'],
        'match_patterns': ['pampered pup', 'pamperedpup', 'the pampered'],
    },
    'TST': {
        'bq_names': ['The Sniff Test'],
        'match_patterns': ['sniff test', 'snifftest', 'the sniff'],
    },
    'CC': {
        'bq_names': ['Cozy Crates'],
        'match_patterns': ['cozy crates', 'cozycrates'],
    },
    'ATNM': {
        'bq_names': ['All Tech No Money'],
        'match_patterns': ['all tech no money', 'alltechnomoney'],
    },
    'BB': {
        'bq_names': ['Better Bets'],
        'match_patterns': ['better bets', 'betterbets'],
    },
    'CH': {
        'bq_names': ['Casino Hunt'],
        'match_patterns': ['casino hunt', 'casinohunt'],
    },
    'PF': {
        'bq_names': ['Privacy Freak'],
        'match_patterns': ['privacy freak', 'privacyfreak'],
    },
    'RZ': {
        'bq_names': ['Reviewszy'],
        'match_patterns': ['reviewszy'],
    },
    'SBS': {
        'bq_names': ['Small Biz Smarts'],
        'match_patterns': ['small biz smarts', 'smallbizsmarts'],
    },
}

ALL_BQ_CHANNEL_NAMES = []
for _ch_data in DIGIDOM_CHANNELS.values():
    ALL_BQ_CHANNEL_NAMES.extend(_ch_data['bq_names'])

ALL_MATCH_PATTERNS = []
for _ch_data in DIGIDOM_CHANNELS.values():
    ALL_MATCH_PATTERNS.extend(_ch_data['match_patterns'])

# ============================================
# DATABASE SETUP (Supabase Postgres)
# ============================================
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:TyV4viBBvAiZiN7y@db.ywfwjvzdbbwgsisdpvlf.supabase.co:5432/postgres')
# Connection pooler URL (more reliable on serverless/Railway — uses pgBouncer on port 6543)
DATABASE_POOLER_URL = os.environ.get('DATABASE_POOLER_URL', 'postgresql://postgres.ywfwjvzdbbwgsisdpvlf:TyV4viBBvAiZiN7y@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres')
# Supabase REST API (always-available fallback when direct Postgres fails)
SUPABASE_REST_URL = os.environ.get('SUPABASE_URL', 'https://ywfwjvzdbbwgsisdpvlf.supabase.co')
SUPABASE_REST_KEY = os.environ.get('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inl3ZndqdnpkYmJ3Z3Npc2RwdmxmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA1MzMyMTksImV4cCI6MjA4NjEwOTIxOX0.M50YzCj8-tkVBblGDjHXGpbEcEGZYvZuZk4PHmpJf8o')
# Keep DB_PATH for migration script reference
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'keyword_data.db')

_last_db_error = None
_db_unreachable_since = None  # Timestamp of first failure; skip retries for 60s


def supabase_rest_select(table, select='*', filters=None, order=None, limit=None, offset=None):
    """Query Supabase via REST API. Returns list of dicts or None on error."""
    try:
        url = f"{SUPABASE_REST_URL}/rest/v1/{table}?select={select}"
        if filters:
            for k, v in filters.items():
                url += f"&{k}={v}"
        if order:
            url += f"&order={order}"
        if limit:
            url += f"&limit={limit}"
        if offset:
            url += f"&offset={offset}"

        req = urllib.request.Request(url, headers={
            'apikey': SUPABASE_REST_KEY,
            'Authorization': f'Bearer {SUPABASE_REST_KEY}',
            'Content-Type': 'application/json'
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[SUPABASE-REST] SELECT {table} error: {e}")
        return None


def supabase_rest_insert(table, rows, upsert=False):
    """Insert rows into Supabase via REST API. rows = list of dicts. Returns True/False."""
    try:
        url = f"{SUPABASE_REST_URL}/rest/v1/{table}"
        data = json.dumps(rows).encode()
        headers = {
            'apikey': SUPABASE_REST_KEY,
            'Authorization': f'Bearer {SUPABASE_REST_KEY}',
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
        }
        if upsert:
            headers['Prefer'] = 'resolution=merge-duplicates,return=minimal'
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        print(f"[SUPABASE-REST] INSERT {table} error: {e}")
        return False

_db_pool = None

def _init_db_pool():
    """Initialize a persistent connection pool to Supabase."""
    global _db_pool
    from psycopg2 import pool as pg_pool
    from urllib.parse import urlparse, unquote

    dsn = DATABASE_POOLER_URL or DATABASE_URL
    if not dsn:
        print("[DB-POOL] No DATABASE_URL configured")
        return

    try:
        parsed = urlparse(dsn)
        _db_pool = pg_pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            host=parsed.hostname,
            port=parsed.port or 5432,
            dbname=parsed.path.lstrip('/') or 'postgres',
            user=unquote(parsed.username or 'postgres'),
            password=unquote(parsed.password or ''),
            connect_timeout=10
        )
        print(f"[DB-POOL] Connection pool initialized (2-10 connections)")
    except Exception as e:
        print(f"[DB-POOL] Failed to create pool: {e}")
        _db_pool = None

# Initialize pool at import time
_init_db_pool()


def get_db():
    """Get a Postgres database connection from the pool.
    Falls back to direct connection if pool unavailable."""
    global _db_pool, _last_db_error, _db_unreachable_since
    from urllib.parse import urlparse, unquote

    # Try pool first (instant — no new TCP connection)
    if _db_pool:
        try:
            conn = _db_pool.getconn()
            conn.autocommit = False
            # Test if connection is alive
            try:
                conn.cursor().execute('SELECT 1')
            except Exception:
                # Connection died, get a fresh one
                _db_pool.putconn(conn, close=True)
                conn = _db_pool.getconn()
                conn.autocommit = False
            _last_db_error = None
            _db_unreachable_since = None
            return conn
        except Exception as e:
            print(f"[DB-POOL] Pool getconn failed: {e}")

    # Skip retries if DB was unreachable in the last 60 seconds
    if _db_unreachable_since and (datetime.now() - _db_unreachable_since).total_seconds() < 60:
        raise ConnectionError(f"[DB] Skipping (unreachable since {_db_unreachable_since.strftime('%H:%M:%S')}): {_last_db_error}")

    errors = []

    # Fallback: direct connection
    dsn = DATABASE_POOLER_URL or DATABASE_URL
    if dsn:
        try:
            parsed = urlparse(dsn)
            conn = psycopg2.connect(
                host=parsed.hostname,
                port=parsed.port or 5432,
                dbname=parsed.path.lstrip('/') or 'postgres',
                user=unquote(parsed.username or 'postgres'),
                password=unquote(parsed.password or ''),
                connect_timeout=5
            )
            conn.autocommit = False
            _last_db_error = None
            _db_unreachable_since = None
            return conn
        except Exception as e:
            errors.append(f"direct: {e}")

    _last_db_error = '; '.join(errors)
    _db_unreachable_since = datetime.now()
    raise ConnectionError(f"[DB] All connection attempts failed: {_last_db_error}")


def release_db(conn):
    """Return a connection to the pool (or close it if not pooled)."""
    global _db_pool
    if _db_pool and conn:
        try:
            _db_pool.putconn(conn)
        except Exception:
            try:
                release_db(conn)
            except Exception:
                pass
    elif conn:
        try:
            release_db(conn)
        except Exception:
            pass

def init_db():
    """Initialize Postgres database tables"""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS keyword_labels (
            id SERIAL PRIMARY KEY,
            keyword TEXT UNIQUE NOT NULL,
            label TEXT DEFAULT 'none',
            is_favorite BOOLEAN DEFAULT FALSE,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            label_updated_by TEXT,
            favorite_updated_by TEXT,
            notes_updated_by TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS researched_keywords (
            id SERIAL PRIMARY KEY,
            keyword TEXT NOT NULL,
            seed_keyword TEXT,
            source TEXT,
            search_volume INTEGER,
            keyword_difficulty DOUBLE PRECISION,
            cpc DOUBLE PRECISION,
            competition TEXT,
            yt_total_views INTEGER,
            yt_avg_views INTEGER,
            yt_video_count INTEGER,
            yt_top_channel TEXT,
            yt_view_pattern TEXT,
            revenue_potential DOUBLE PRECISION,
            priority_score DOUBLE PRECISION,
            opportunity_tier TEXT,
            niche TEXT,
            funnel_stage TEXT,
            researched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(keyword, source)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS revenue_data (
            id SERIAL PRIMARY KEY,
            keyword TEXT NOT NULL,
            video_url TEXT,
            video_views INTEGER,
            affiliate_clicks INTEGER,
            conversions INTEGER,
            revenue DOUBLE PRECISION,
            period_start DATE,
            period_end DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS ranking_history (
            id SERIAL PRIMARY KEY,
            keyword TEXT NOT NULL,
            revenue DOUBLE PRECISION,
            domination_score DOUBLE PRECISION,
            positions_owned TEXT,
            snapshot_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS domination_audits (
            id SERIAL PRIMARY KEY,
            audit_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS keyword_dom_targets (
            keyword TEXT PRIMARY KEY,
            target_dom_score INTEGER DEFAULT 100,
            updated_by TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS keyword_yt_data (
            id SERIAL PRIMARY KEY,
            keyword TEXT UNIQUE NOT NULL,
            yt_avg_views INTEGER,
            yt_view_pattern TEXT,
            yt_top_video_title TEXT,
            yt_top_video_views INTEGER,
            yt_top_video_channel TEXT,
            yt_total_views INTEGER,
            yt_video_count INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS keyword_votes (
            id SERIAL PRIMARY KEY,
            keyword TEXT NOT NULL,
            user_email TEXT NOT NULL,
            user_name TEXT,
            vote INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(keyword, user_email)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS keyword_comments (
            id SERIAL PRIMARY KEY,
            keyword TEXT NOT NULL,
            user_email TEXT NOT NULL,
            user_name TEXT,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS keyword_additions (
            id SERIAL PRIMARY KEY,
            keyword TEXT NOT NULL,
            user_email TEXT NOT NULL,
            user_name TEXT,
            source TEXT DEFAULT 'manual',
            source_detail TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(keyword, user_email)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS keyword_trends (
            id SERIAL PRIMARY KEY,
            keyword TEXT UNIQUE NOT NULL,
            trend TEXT DEFAULT 'unknown',
            trend_change_pct DOUBLE PRECISION DEFAULT 0,
            current_interest INTEGER DEFAULT 0,
            data_points INTEGER DEFAULT 0,
            peak_months TEXT DEFAULT NULL,
            low_months TEXT DEFAULT NULL,
            seasonality_score INTEGER DEFAULT 0,
            publish_window TEXT DEFAULT NULL,
            monthly_averages JSONB DEFAULT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add seasonal columns to existing keyword_trends tables
    for col, col_type in [
        ('peak_months', 'TEXT DEFAULT NULL'),
        ('low_months', 'TEXT DEFAULT NULL'),
        ('seasonality_score', 'INTEGER DEFAULT 0'),
        ('publish_window', 'TEXT DEFAULT NULL'),
        ('monthly_averages', 'JSONB DEFAULT NULL'),
    ]:
        try:
            c.execute(f'ALTER TABLE keyword_trends ADD COLUMN IF NOT EXISTS {col} {col_type}')
        except Exception:
            pass

    # Ensure created_at exists on keyword_additions (may be missing on older DBs)
    try:
        c.execute("ALTER TABLE keyword_additions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    except Exception:
        pass

    c.execute('''
        CREATE TABLE IF NOT EXISTS bq_cache (
            cache_key TEXT PRIMARY KEY,
            data JSONB NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS keywords_master (
            id SERIAL PRIMARY KEY,
            keyword TEXT UNIQUE NOT NULL,
            niche TEXT DEFAULT '',
            funnel TEXT DEFAULT '',
            intent_type TEXT DEFAULT '',
            volume INTEGER DEFAULT 0,
            commission DOUBLE PRECISION DEFAULT 0,
            revenue_potential DOUBLE PRECISION DEFAULT 0,
            buying_intent INTEGER DEFAULT 0,
            yt_avg_monthly_views INTEGER DEFAULT 0,
            yt_view_pattern TEXT DEFAULT '',
            priority_score DOUBLE PRECISION DEFAULT 0,
            opportunity_tier TEXT DEFAULT '',
            competition TEXT DEFAULT '',
            content_angle TEXT DEFAULT '',
            rationale TEXT DEFAULT '',
            conversion_likelihood TEXT DEFAULT '',
            time_to_convert TEXT DEFAULT '',
            problem_type TEXT DEFAULT '',
            urgency_score INTEGER DEFAULT 0,
            yt_top_video_title TEXT DEFAULT '',
            yt_top_video_views INTEGER DEFAULT 0,
            yt_top_video_channel TEXT DEFAULT '',
            added_by_email TEXT DEFAULT 'system',
            added_by_name TEXT DEFAULT 'CSV Import',
            source TEXT DEFAULT 'csv',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS priority_keywords (
            id SERIAL PRIMARY KEY,
            keyword TEXT UNIQUE NOT NULL,
            tier TEXT DEFAULT 'A',
            niche TEXT DEFAULT '',
            priority_score REAL DEFAULT 0,
            search_volume INTEGER DEFAULT 0,
            source TEXT DEFAULT 'tracking',
            is_active BOOLEAN DEFAULT TRUE,
            added_by TEXT DEFAULT 'system',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    release_db(conn)

try:
    init_db()
except Exception as e:
    print(f"[DB] Warning: Could not initialize DB (tables may already exist): {e}")


def seed_priority_keywords():
    """Seed priority_keywords table from keyword_tracking.json (22 primary keywords).
    Only runs if the table is empty. CSV keywords loaded as inactive for browsing.
    Uses autocommit mode to avoid Supabase statement_timeout on long transactions."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM priority_keywords')
        count = c.fetchone()[0]
        if count > 0:
            print(f"[SEED] priority_keywords already has {count} rows, skipping seed")
            release_db(conn)
            return
        release_db(conn)

        # Re-open with autocommit to avoid Supabase statement_timeout
        conn = get_db()
        conn.autocommit = True
        c = conn.cursor()

        # Source 1: keyword_tracking.json — 22 primary keywords as ACTIVE defaults
        tracking_path = os.path.join(os.path.dirname(__file__), 'data', 'keyword_tracking.json')
        tracking_keywords = set()
        if os.path.exists(tracking_path):
            with open(tracking_path) as f:
                config = json.load(f)
            for silo in config.get('silos', []):
                silo_id = silo.get('id', '')
                for group in silo.get('groups', []):
                    for kw_entry in group.get('keywords', []):
                        kw = kw_entry['keyword'].lower().strip()
                        tracking_keywords.add(kw)
                        c.execute('''
                            INSERT INTO priority_keywords (keyword, tier, niche, priority_score, source, is_active, added_by)
                            VALUES (%s, 'A', %s, 100, 'tracking', TRUE, 'system')
                            ON CONFLICT (keyword) DO NOTHING
                        ''', (kw, silo_id))
                        # Also add secondaries as active (included in audits)
                        for sec in kw_entry.get('secondary', []):
                            sec_kw = sec.lower().strip()
                            tracking_keywords.add(sec_kw)
                            c.execute('''
                                INSERT INTO priority_keywords (keyword, tier, niche, priority_score, source, is_active, added_by)
                                VALUES (%s, 'A', %s, 90, 'tracking', TRUE, 'system')
                                ON CONFLICT (keyword) DO NOTHING
                            ''', (sec_kw, silo_id))
            print(f"[SEED] Inserted {len(tracking_keywords)} keywords from keyword_tracking.json (active)")

        # Source 2: keywords.csv — remaining keywords as INACTIVE (available to activate)
        csv_path = os.path.join(os.path.dirname(__file__), 'data', 'keywords.csv')
        csv_count = 0
        if os.path.exists(csv_path):
            import csv as csv_mod
            with open(csv_path) as f:
                reader = csv_mod.DictReader(f)
                for row in reader:
                    kw = row.get('keyword', '').lower().strip()
                    if not kw or kw in tracking_keywords:
                        continue
                    tier_raw = row.get('opportunity_tier', '').strip()
                    tier = tier_raw[0] if tier_raw else 'D'  # A, B, C, D
                    niche = row.get('niche', '').strip()
                    score = float(row.get('priority_score', 0) or 0)
                    volume = int(row.get('volume', 0) or 0)
                    c.execute('''
                        INSERT INTO priority_keywords (keyword, tier, niche, priority_score, search_volume, source, is_active, added_by)
                        VALUES (%s, %s, %s, %s, %s, 'csv', FALSE, 'system')
                        ON CONFLICT (keyword) DO NOTHING
                    ''', (kw, tier, niche, score, volume))
                    csv_count += 1
            print(f"[SEED] Inserted {csv_count} keywords from keywords.csv (inactive)")

        release_db(conn)
        print(f"[SEED] Priority keywords seeded successfully")
    except Exception as e:
        print(f"[SEED] Error seeding priority_keywords: {e}")

try:
    seed_priority_keywords()
except Exception as e:
    print(f"[SEED] Warning: Could not seed priority keywords: {e}")

# Startup migration: add is_primary/parent_keyword columns + seed relationships from tracking JSON
try:
    _conn = get_db()
    _conn.autocommit = True
    _c = _conn.cursor()
    # Add columns if missing
    _c.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'priority_keywords' AND column_name = 'is_primary'")
    if not _c.fetchone():
        _c.execute("ALTER TABLE priority_keywords ADD COLUMN is_primary BOOLEAN DEFAULT FALSE")
        _c.execute("ALTER TABLE priority_keywords ADD COLUMN parent_keyword TEXT DEFAULT ''")
        print("[SEED-FIX] Added is_primary and parent_keyword columns")

    # Seed primary/secondary relationships from keyword_tracking.json
    tracking_path = os.path.join(os.path.dirname(__file__), 'data', 'keyword_tracking.json')
    if os.path.exists(tracking_path):
        with open(tracking_path) as f:
            _cfg = json.load(f)
        _fixed = 0
        for _silo in _cfg.get('silos', []):
            for _grp in _silo.get('groups', []):
                for _ke in _grp.get('keywords', []):
                    _pk = _ke['keyword'].lower().strip()
                    # Mark primary
                    _c.execute("UPDATE priority_keywords SET is_primary = TRUE, is_active = TRUE WHERE keyword = %s AND is_primary IS NOT TRUE", (_pk,))
                    _fixed += _c.rowcount
                    # Mark secondaries with parent
                    for _s in _ke.get('secondary', []):
                        _sk = _s.lower().strip()
                        _c.execute("UPDATE priority_keywords SET is_primary = FALSE, parent_keyword = %s, is_active = TRUE WHERE keyword = %s AND (parent_keyword IS NULL OR parent_keyword = '')", (_pk, _sk))
                        _fixed += _c.rowcount
        if _fixed > 0:
            print(f"[SEED-FIX] Updated {_fixed} keyword relationships from tracking JSON")
    _release_db(conn)
except Exception as e:
    print(f"[SEED-FIX] Warning: {e}")

# ============================================
# CSV → DB MIGRATION (one-time import into Supabase)
# ============================================
def migrate_csv_to_db():
    """Import CSV keywords into keywords_master table if not already done"""
    try:
        conn = get_db()
    except Exception as e:
        print(f"[MIGRATION] Cannot connect to DB, skipping: {e}")
        return
    c = conn.cursor()

    c.execute('SELECT COUNT(*) FROM keywords_master')
    if c.fetchone()[0] > 0:
        print("[MIGRATION] keywords_master already populated, skipping CSV import")
        release_db(conn)
        return

    csv_path = os.path.join(os.path.dirname(__file__), 'data', 'keywords.csv')
    if not os.path.exists(csv_path):
        print("[MIGRATION] CSV file not found, skipping")
        release_db(conn)
        return

    imported = 0
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            keyword = row.get('keyword', '').strip()
            if not keyword:
                continue
            try:
                c.execute('''
                    INSERT INTO keywords_master
                    (keyword, niche, funnel, intent_type, volume, commission,
                     revenue_potential, buying_intent, yt_avg_monthly_views, yt_view_pattern,
                     priority_score, opportunity_tier, competition, content_angle, rationale,
                     conversion_likelihood, time_to_convert, problem_type, urgency_score,
                     yt_top_video_title, yt_top_video_views, yt_top_video_channel,
                     added_by_email, added_by_name, source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (keyword) DO NOTHING
                ''', (
                    keyword,
                    row.get('niche', ''),
                    row.get('funnel', ''),
                    row.get('intent_type', ''),
                    int(float(row.get('volume', 0) or 0)),
                    float(row.get('commission', 0) or 0),
                    float(row.get('revenue_potential', 0) or 0),
                    int(float(row.get('buying_intent', 0) or 0)),
                    int(float(row.get('yt_avg_monthly_views', 0) or 0)),
                    row.get('yt_view_pattern', ''),
                    float(row.get('priority_score', 0) or 0),
                    row.get('opportunity_tier', ''),
                    row.get('competition', ''),
                    row.get('content_angle', ''),
                    row.get('rationale', ''),
                    row.get('conversion_likelihood', ''),
                    row.get('time_to_convert', ''),
                    row.get('problem_type', ''),
                    int(float(row.get('urgency_score', 0) or 0)),
                    row.get('yt_top_video_title', ''),
                    int(float(row.get('yt_top_video_views', 0) or 0)),
                    row.get('yt_top_video_channel', ''),
                    'system', 'CSV Import', 'csv'
                ))
                imported += 1
            except Exception as e:
                print(f"[MIGRATION] Error importing '{keyword}': {e}")

    conn.commit()
    release_db(conn)
    print(f"[MIGRATION] Imported {imported} keywords from CSV into keywords_master")

migrate_csv_to_db()

# ============================================
# LOAD KEYWORDS FROM DATABASE (keywords_master)
# ============================================
def _load_keywords_from_csv():
    """Load keywords from CSV file as fallback."""
    keywords = []
    csv_path = os.path.join(os.path.dirname(__file__), 'data', 'keywords.csv')
    if os.path.exists(csv_path):
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('keyword'):
                    keywords.append({
                        'keyword': row.get('keyword', ''),
                        'niche': row.get('niche', ''),
                        'funnel': row.get('funnel', ''),
                        'intent': row.get('intent_type', ''),
                        'volume': int(float(row.get('volume', 0) or 0)),
                        'commission': float(row.get('commission', 0) or 0),
                        'revenue': float(row.get('revenue_potential', 0) or 0),
                        'buyingIntent': int(float(row.get('buying_intent', 0) or 0)),
                        'ytViews': int(float(row.get('yt_avg_monthly_views', 0) or 0)),
                        'ytPattern': row.get('yt_view_pattern', ''),
                        'priority': float(row.get('priority_score', 0) or 0),
                        'tier': row.get('opportunity_tier', ''),
                        'competition': row.get('competition', ''),
                        'contentAngle': row.get('content_angle', ''),
                        'rationale': row.get('rationale', ''),
                        'conversionLikelihood': row.get('conversion_likelihood', ''),
                        'timeToConvert': row.get('time_to_convert', ''),
                        'problemType': row.get('problem_type', ''),
                        'urgencyScore': int(float(row.get('urgency_score', 0) or 0)),
                        'ytTopVideo': row.get('yt_top_video_title', ''),
                        'ytTopViews': int(float(row.get('yt_top_video_views', 0) or 0)),
                        'ytTopChannel': row.get('yt_top_video_channel', ''),
                        'addedByEmail': 'system',
                        'addedByName': 'CSV Import',
                        'source': 'csv',
                    })
    return keywords


def _row_to_keyword(row):
    """Convert a DB row (25 columns) to keyword dict."""
    return {
        'keyword': row[0] or '',
        'niche': row[1] or '',
        'funnel': row[2] or '',
        'intent': row[3] or '',
        'volume': row[4] or 0,
        'commission': row[5] or 0,
        'revenue': row[6] or 0,
        'buyingIntent': row[7] or 0,
        'ytViews': row[8] or 0,
        'ytPattern': row[9] or '',
        'priority': row[10] or 0,
        'tier': row[11] or '',
        'competition': row[12] or '',
        'contentAngle': row[13] or '',
        'rationale': row[14] or '',
        'conversionLikelihood': row[15] or '',
        'timeToConvert': row[16] or '',
        'problemType': row[17] or '',
        'urgencyScore': row[18] or 0,
        'ytTopVideo': row[19] or '',
        'ytTopViews': row[20] or 0,
        'ytTopChannel': row[21] or '',
        'addedByEmail': row[22] or 'system',
        'addedByName': row[23] or '',
        'source': row[24] or 'csv',
    }


def _load_keywords_from_rest_api():
    """Load keywords from Supabase REST API when direct Postgres fails."""
    import time as _time
    start_time = _time.time()
    max_seconds = 60  # Bail out after 60s to avoid gunicorn timeout
    select = 'keyword,niche,funnel,intent_type,volume,commission,revenue_potential,buying_intent,yt_avg_monthly_views,yt_view_pattern,priority_score,opportunity_tier,competition,content_angle,rationale,conversion_likelihood,time_to_convert,problem_type,urgency_score,yt_top_video_title,yt_top_video_views,yt_top_video_channel,added_by_email,added_by_name,source'
    # Supabase REST API has a default limit of 1000 rows — paginate to get all
    keywords = []
    offset = 0
    page_size = 1000
    while True:
        if _time.time() - start_time > max_seconds:
            print(f"[SUPABASE-REST] Timeout after {max_seconds}s, loaded {len(keywords)} keywords so far")
            break
        rows = supabase_rest_select('keywords_master', select=select, limit=page_size,
                                     offset=offset)
        if rows is None:
            break
        for r in rows:
            keywords.append({
                'keyword': r.get('keyword', ''),
                'niche': r.get('niche', ''),
                'funnel': r.get('funnel', ''),
                'intent': r.get('intent_type', ''),
                'volume': r.get('volume') or 0,
                'commission': r.get('commission') or 0,
                'revenue': r.get('revenue_potential') or 0,
                'buyingIntent': r.get('buying_intent') or 0,
                'ytViews': r.get('yt_avg_monthly_views') or 0,
                'ytPattern': r.get('yt_view_pattern') or '',
                'priority': r.get('priority_score') or 0,
                'tier': r.get('opportunity_tier') or '',
                'competition': r.get('competition') or '',
                'contentAngle': r.get('content_angle') or '',
                'rationale': r.get('rationale') or '',
                'conversionLikelihood': r.get('conversion_likelihood') or '',
                'timeToConvert': r.get('time_to_convert') or '',
                'problemType': r.get('problem_type') or '',
                'urgencyScore': r.get('urgency_score') or 0,
                'ytTopVideo': r.get('yt_top_video_title') or '',
                'ytTopViews': r.get('yt_top_video_views') or 0,
                'ytTopChannel': r.get('yt_top_video_channel') or '',
                'addedByEmail': r.get('added_by_email') or 'system',
                'addedByName': r.get('added_by_name') or '',
                'source': r.get('source') or 'csv',
            })
        if len(rows) < page_size:
            break
        offset += page_size
    return keywords


def load_keywords():
    """Load all keywords from the keywords_master database table.
    Fallback chain: direct Postgres → Supabase REST API → CSV file."""
    keywords = []

    # Attempt 1: Direct Postgres
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT keyword, niche, funnel, intent_type, volume, commission,
                   revenue_potential, buying_intent, yt_avg_monthly_views, yt_view_pattern,
                   priority_score, opportunity_tier, competition, content_angle, rationale,
                   conversion_likelihood, time_to_convert, problem_type, urgency_score,
                   yt_top_video_title, yt_top_video_views, yt_top_video_channel,
                   added_by_email, added_by_name, source
            FROM keywords_master
        ''')
        for row in c.fetchall():
            keywords.append(_row_to_keyword(row))
        release_db(conn)
        if keywords:
            print(f"[KEYWORDS] Loaded {len(keywords)} keywords from Postgres")
            return keywords
    except Exception as e:
        print(f"[KEYWORDS] Postgres failed: {e}")

    # Attempt 2: Supabase REST API
    if not keywords:
        print("[KEYWORDS] Trying Supabase REST API...")
        keywords = _load_keywords_from_rest_api()
        if keywords:
            print(f"[KEYWORDS] Loaded {len(keywords)} keywords from REST API")
            return keywords

    # Attempt 3: CSV file
    print("[KEYWORDS] REST API returned 0, falling back to CSV")
    keywords = _load_keywords_from_csv()
    if keywords:
        print(f"[KEYWORDS] Loaded {len(keywords)} keywords from CSV fallback")

    return keywords

KEYWORDS = load_keywords()
print(f"[KEYWORDS] Total keywords available: {len(KEYWORDS)}")


def ensure_tracking_keywords_in_master():
    """Import keyword_tracking.json primary + secondary keywords into keywords_master.
    Ensures the 26 priority keywords (and their secondaries) always appear in the library."""
    tracking_path = os.path.join(os.path.dirname(__file__), 'data', 'keyword_tracking.json')
    if not os.path.exists(tracking_path):
        print("[TRACKING-IMPORT] keyword_tracking.json not found, skipping")
        return 0

    try:
        with open(tracking_path, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"[TRACKING-IMPORT] Error reading tracking config: {e}")
        return 0

    try:
        conn = get_db()
        c = conn.cursor()
        inserted = 0

        for silo in config.get('silos', []):
            silo_id = silo.get('id', '')
            niche = silo_id.replace('_', ' ')
            for group in silo.get('groups', []):
                for kw_entry in group.get('keywords', []):
                    # Insert primary keyword
                    keyword = kw_entry['keyword']
                    try:
                        c.execute('''
                            INSERT INTO keywords_master (keyword, niche, source, added_by_email, added_by_name)
                            VALUES (%s, %s, 'tracking', 'system', 'Tracking Config')
                            ON CONFLICT (keyword) DO NOTHING
                        ''', (keyword, niche))
                        if c.rowcount > 0:
                            inserted += 1
                    except Exception:
                        pass

                    # Insert secondary keywords
                    for sec in kw_entry.get('secondary', []):
                        try:
                            c.execute('''
                                INSERT INTO keywords_master (keyword, niche, source, added_by_email, added_by_name)
                                VALUES (%s, %s, 'tracking_secondary', 'system', 'Tracking Config')
                                ON CONFLICT (keyword) DO NOTHING
                            ''', (sec, niche))
                            if c.rowcount > 0:
                                inserted += 1
                        except Exception:
                            pass

        conn.commit()
        release_db(conn)
        if inserted > 0:
            print(f"[TRACKING-IMPORT] Inserted {inserted} new keywords from tracking config into keywords_master")
            # Reload global KEYWORDS list to include newly added keywords
            global KEYWORDS
            KEYWORDS = load_keywords()
            print(f"[TRACKING-IMPORT] Reloaded KEYWORDS, now {len(KEYWORDS)} total")
        else:
            print("[TRACKING-IMPORT] All tracking keywords already in keywords_master")
        return inserted
    except Exception as e:
        print(f"[TRACKING-IMPORT] Error importing tracking keywords: {e}")
        return 0


try:
    ensure_tracking_keywords_in_master()
except Exception as e:
    print(f"[TRACKING-IMPORT] Warning: {e}")


# ============================================
# API INTEGRATIONS
# ============================================

# Log API key status on startup
print(f"Ahrefs API key configured: {bool(AHREFS_API_KEY)} (length: {len(AHREFS_API_KEY)})")

def get_ahrefs_keyword_data(keywords):
    """
    Get keyword data from Ahrefs API v3 Keywords Explorer.
    Returns search volume, difficulty, CPC for keywords.
    """
    try:
        if isinstance(keywords, str):
            keywords = [keywords]

        if not AHREFS_API_KEY:
            return {'success': False, 'error': 'Ahrefs API key not configured', 'source': 'ahrefs'}

        results = []

        # Ahrefs API processes keywords one at a time or in batches
        for keyword in keywords:
            url = "https://api.ahrefs.com/v3/keywords-explorer/overview"
            headers = {
                "Authorization": f"Bearer {AHREFS_API_KEY}",
                "Accept": "application/json"
            }
            params = {
                "keyword": keyword,
                "country": "us"
            }

            print(f"Calling Ahrefs API for keyword: {keyword}")
            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                # Extract relevant metrics from Ahrefs response
                keyword_data = {
                    'keyword': keyword,
                    'vol': data.get('volume', 0),
                    'cpc': {'currency': '$', 'value': str(data.get('cpc', 0))},
                    'competition': data.get('difficulty', 0) / 100 if data.get('difficulty') else 0,
                    'difficulty': data.get('difficulty', 0),
                    'trend': data.get('trend', [])
                }
                results.append(keyword_data)
            elif response.status_code == 401:
                return {'success': False, 'error': 'Ahrefs API key is invalid or expired', 'source': 'ahrefs'}
            elif response.status_code == 403:
                return {'success': False, 'error': 'Ahrefs API access denied - requires Enterprise plan', 'source': 'ahrefs'}
            else:
                print(f"Ahrefs API error for {keyword}: {response.status_code} - {response.text[:200]}")

        if results:
            return {'success': True, 'data': results, 'source': 'ahrefs'}
        else:
            return {'success': False, 'error': 'No data returned from Ahrefs', 'source': 'ahrefs'}

    except Exception as e:
        print(f"Ahrefs API exception: {e}")
        return {'success': False, 'error': str(e), 'source': 'ahrefs'}

def get_ahrefs_related_keywords(keyword):
    """Get related keywords from Ahrefs API v3"""
    try:
        if not AHREFS_API_KEY:
            return {'success': False, 'error': 'Ahrefs API key not configured', 'source': 'ahrefs'}

        url = "https://api.ahrefs.com/v3/keywords-explorer/related-terms"
        headers = {
            "Authorization": f"Bearer {AHREFS_API_KEY}",
            "Accept": "application/json"
        }
        params = {
            "keyword": keyword,
            "country": "us",
            "limit": 50
        }

        response = requests.get(url, headers=headers, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            related = data.get('keywords', [])
            return {'success': True, 'related': related, 'source': 'ahrefs'}
        elif response.status_code == 401:
            return {'success': False, 'error': 'Ahrefs API key is invalid', 'source': 'ahrefs'}
        elif response.status_code == 403:
            return {'success': False, 'error': 'Ahrefs API access denied', 'source': 'ahrefs'}
        else:
            return {'success': False, 'error': f'Ahrefs API error: {response.status_code}', 'source': 'ahrefs'}

    except Exception as e:
        return {'success': False, 'error': str(e), 'source': 'ahrefs'}

def get_dataforseo_keyword_data(keywords):
    """
    Get keyword data from DataForSEO API.
    Returns search volume, CPC, competition for keywords.
    Uses Google Ads Search Volume endpoint.
    """
    try:
        if isinstance(keywords, str):
            keywords = [keywords]

        if not DATAFORSEO_LOGIN or not DATAFORSEO_PASSWORD:
            return {'success': False, 'error': 'DataForSEO credentials not configured', 'source': 'dataforseo'}

        import base64

        # DataForSEO uses Basic Auth
        credentials = base64.b64encode(f"{DATAFORSEO_LOGIN}:{DATAFORSEO_PASSWORD}".encode()).decode()

        url = "https://api.dataforseo.com/v3/keywords_data/google_ads/search_volume/live"
        headers = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json"
        }

        # Build request payload
        payload = [{
            "keywords": keywords[:700],  # Max 700 keywords per request
            "language_code": "en",
            "location_code": 2840  # United States
        }]

        print(f"Calling DataForSEO API for {len(keywords)} keywords: {keywords}")
        response = requests.post(url, headers=headers, json=payload, timeout=60)

        print(f"DataForSEO response status: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"DataForSEO response: status_code={data.get('status_code')}, status_message={data.get('status_message')}")

            # Check for API-level errors
            if data.get('status_code') != 20000:
                return {
                    'success': False,
                    'error': f"DataForSEO error: {data.get('status_message', 'Unknown error')} (code: {data.get('status_code')})",
                    'source': 'dataforseo'
                }

            # Extract keyword data from response
            results = []
            tasks = data.get('tasks', [])
            print(f"DataForSEO tasks count: {len(tasks)}")

            for task in tasks:
                print(f"Task status: {task.get('status_code')}, message: {task.get('status_message')}")
                if task.get('status_code') == 20000:
                    task_result = task.get('result', [])
                    print(f"Task result count: {len(task_result) if task_result else 0}")

                    if task_result:
                        for item in task_result:
                            print(f"Item keys: {item.keys() if item else 'None'}")

                            # Convert competition to numeric (DataForSEO returns "LOW", "MEDIUM", "HIGH" or null)
                            competition_raw = item.get('competition')
                            competition_index = item.get('competition_index', 0) or 0

                            # Use competition_index if available, otherwise convert string
                            if isinstance(competition_index, (int, float)) and competition_index > 0:
                                competition = competition_index / 100  # Normalize to 0-1
                            elif isinstance(competition_raw, str):
                                # Convert string to numeric
                                comp_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.8}
                                competition = comp_map.get(competition_raw.upper(), 0.5)
                            elif isinstance(competition_raw, (int, float)):
                                competition = float(competition_raw)
                            else:
                                competition = 0

                            results.append({
                                'keyword': item.get('keyword', ''),
                                'vol': item.get('search_volume', 0) or 0,
                                'cpc': {
                                    'currency': '$',
                                    'value': str(round(float(item.get('cpc', 0) or 0), 2))
                                },
                                'competition': competition,
                                'competition_index': competition_index,
                                'low_top_of_page_bid': item.get('low_top_of_page_bid', 0) or 0,
                                'high_top_of_page_bid': item.get('high_top_of_page_bid', 0) or 0,
                                'monthly_searches': item.get('monthly_searches', []),
                                'source': 'dataforseo'
                            })

            print(f"DataForSEO success: got data for {len(results)} keywords")

            if not results:
                # Return more info about what went wrong
                return {
                    'success': False,
                    'error': f"DataForSEO returned empty results. Tasks: {len(tasks)}, Response: {str(data)[:500]}",
                    'source': 'dataforseo'
                }

            return {'success': True, 'data': results, 'source': 'dataforseo'}

        elif response.status_code == 401:
            return {'success': False, 'error': 'DataForSEO credentials invalid', 'source': 'dataforseo'}
        else:
            error_msg = f"DataForSEO API error: {response.status_code}"
            try:
                error_data = response.json()
                error_msg += f" - {error_data.get('status_message', '')}"
            except:
                error_msg += f" - {response.text[:200]}"
            return {'success': False, 'error': error_msg, 'source': 'dataforseo'}

    except Exception as e:
        print(f"DataForSEO exception: {e}")
        return {'success': False, 'error': str(e), 'source': 'dataforseo'}

def get_dataforseo_related_keywords(keyword):
    """
    Get related keywords from DataForSEO using keyword suggestions endpoint.
    """
    try:
        if not DATAFORSEO_LOGIN or not DATAFORSEO_PASSWORD:
            return {'success': False, 'error': 'DataForSEO credentials not configured', 'source': 'dataforseo'}

        import base64
        credentials = base64.b64encode(f"{DATAFORSEO_LOGIN}:{DATAFORSEO_PASSWORD}".encode()).decode()

        url = "https://api.dataforseo.com/v3/keywords_data/google_ads/keywords_for_keywords/live"
        headers = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json"
        }

        payload = [{
            "keywords": [keyword],
            "language_code": "en",
            "location_code": 2840  # United States
        }]

        response = requests.post(url, headers=headers, json=payload, timeout=60)

        if response.status_code == 200:
            data = response.json()

            if data.get('status_code') != 20000:
                return {'success': False, 'error': f"DataForSEO error: {data.get('status_message')}", 'source': 'dataforseo'}

            related = []
            tasks = data.get('tasks', [])

            for task in tasks:
                if task.get('status_code') == 20000:
                    task_result = task.get('result', [])
                    for item in task_result:
                        related.append({
                            'keyword': item.get('keyword', ''),
                            'vol': item.get('search_volume', 0),
                            'cpc': item.get('cpc', 0),
                            'competition': item.get('competition', 0),
                            'source': 'dataforseo'
                        })

            return {'success': True, 'related': related[:50], 'source': 'dataforseo'}

        elif response.status_code == 401:
            return {'success': False, 'error': 'DataForSEO credentials invalid', 'source': 'dataforseo'}
        else:
            return {'success': False, 'error': f'DataForSEO error: {response.status_code}', 'source': 'dataforseo'}

    except Exception as e:
        return {'success': False, 'error': str(e), 'source': 'dataforseo'}

def get_keyword_data_with_fallback(keywords):
    """
    Fallback chain: DataForSEO → Ahrefs → Keywords Everywhere → SerpAPI
    DataForSEO is preferred as it provides accurate search volume at low cost.
    """
    # Try DataForSEO first (best value - accurate data, pay per use)
    if DATAFORSEO_LOGIN and DATAFORSEO_PASSWORD:
        print("Trying DataForSEO API first...")
        dfs_result = get_dataforseo_keyword_data(keywords)
        if dfs_result.get('success'):
            return dfs_result
        else:
            print(f"DataForSEO failed: {dfs_result.get('error')}, trying next...")

    # Try Ahrefs (if configured)
    if AHREFS_API_KEY:
        print("Trying Ahrefs API...")
        ahrefs_result = get_ahrefs_keyword_data(keywords)
        if ahrefs_result.get('success'):
            return ahrefs_result
        else:
            print(f"Ahrefs failed: {ahrefs_result.get('error')}, trying next...")

    # Fall back to Keywords Everywhere
    if KEYWORDS_EVERYWHERE_API_KEY:
        print("Trying Keywords Everywhere API...")
        ke_result = get_keywords_everywhere_data(keywords)
        if ke_result.get('success'):
            return ke_result
        else:
            print(f"Keywords Everywhere failed: {ke_result.get('error')}, trying SerpAPI...")

    # Final fallback: SerpAPI (trends data, no exact volume)
    if SERPAPI_API_KEY:
        print("Using SerpAPI for keyword trends (no exact volume)...")
        if isinstance(keywords, str):
            keywords = [keywords]

        serpapi_data = []
        for kw in keywords[:10]:  # Limit to avoid too many API calls
            trend_data = get_serpapi_google_trends(kw)
            serpapi_data.append({
                'keyword': kw,
                'vol': trend_data.get('current_interest', 0) * 100,  # Scale 0-100 to estimated volume
                'trend': trend_data.get('trend', 'unknown'),
                'trend_change_pct': trend_data.get('trend_change_pct', 0),
                'cpc': {'currency': '$', 'value': '0'},  # Not available from SerpAPI
                'competition': 0,  # Not available from SerpAPI
                'source': 'serpapi_trends'
            })

        return {
            'success': True,
            'data': serpapi_data,
            'source': 'serpapi_trends',
            'note': 'Using Google Trends data - volume is relative interest (0-100 scaled), not exact monthly searches'
        }

    # Nothing configured
    return {
        'success': False,
        'error': 'No keyword API configured. Please add DATAFORSEO credentials, AHREFS_API_KEY, KEYWORDS_EVERYWHERE_API_KEY, or SERPAPI_API_KEY.',
        'source': 'none'
    }

def get_related_keywords_with_fallback(keyword):
    """
    Fallback chain: DataForSEO → Ahrefs → Keywords Everywhere → SerpAPI
    """
    # Try DataForSEO first (best value)
    if DATAFORSEO_LOGIN and DATAFORSEO_PASSWORD:
        dfs_result = get_dataforseo_related_keywords(keyword)
        if dfs_result.get('success'):
            return dfs_result

    # Try Ahrefs
    if AHREFS_API_KEY:
        ahrefs_result = get_ahrefs_related_keywords(keyword)
        if ahrefs_result.get('success'):
            return ahrefs_result

    # Fall back to Keywords Everywhere
    if KEYWORDS_EVERYWHERE_API_KEY:
        ke_result = get_keywords_everywhere_related(keyword)
        if ke_result.get('success'):
            return ke_result

    # Final fallback: SerpAPI (autocomplete + related queries)
    if SERPAPI_API_KEY:
        print("Using SerpAPI for related keywords...")

        all_related = []

        # Get autocomplete suggestions
        autocomplete = get_serpapi_autocomplete(keyword)
        if autocomplete.get('success'):
            for s in autocomplete.get('suggestions', []):
                all_related.append({
                    'keyword': s.get('keyword', ''),
                    'source': 'autocomplete'
                })

        # Get Google Trends related queries
        related_queries = get_serpapi_related_queries(keyword)
        if related_queries.get('success'):
            for r in related_queries.get('related', []):
                all_related.append({
                    'keyword': r.get('keyword', ''),
                    'trend_type': r.get('trend_type', ''),
                    'source': 'trends_related'
                })

        return {
            'success': True,
            'related': all_related,
            'source': 'serpapi'
        }

    return {'success': False, 'error': 'No keyword API configured', 'source': 'none'}

def get_keywords_everywhere_data(keywords):
    try:
        if isinstance(keywords, str):
            keywords = [keywords]

        if not KEYWORDS_EVERYWHERE_API_KEY:
            return {'success': False, 'error': 'Keywords Everywhere API key not configured. Please add KEYWORDS_EVERYWHERE_API_KEY to your Railway environment variables.', 'source': 'keywords_everywhere'}

        url = "https://api.keywordseverywhere.com/v1/get_keyword_data"
        headers = {
            "Authorization": f"Bearer {KEYWORDS_EVERYWHERE_API_KEY}",
            "Accept": "application/json"
        }

        # Build form data with proper kw[] format for multiple keywords
        data = [
            ("country", "us"),
            ("currency", "usd"),
            ("dataSource", "gkp"),
        ]
        # Add each keyword as separate kw[] parameter
        for kw in keywords:
            data.append(("kw[]", kw))

        print(f"Calling Keywords Everywhere API for {len(keywords)} keywords...")
        response = requests.post(url, headers=headers, data=data, timeout=30)

        if response.status_code == 200:
            result = response.json()
            print(f"Keywords Everywhere API success: got data for {len(result.get('data', []))} keywords")
            return {'success': True, 'data': result.get('data', []), 'source': 'keywords_everywhere'}
        elif response.status_code == 401:
            # Specific handling for authentication errors
            return {'success': False, 'error': 'Keywords Everywhere API key is invalid or expired. Please get a fresh API key from keywordseverywhere.com/settings.html and update the KEYWORDS_EVERYWHERE_API_KEY in Railway.', 'source': 'keywords_everywhere'}
        else:
            # Log the actual error for debugging
            error_msg = f"Keywords Everywhere API error: {response.status_code}"
            try:
                error_detail = response.json()
                error_msg += f" - {error_detail.get('message', response.text[:200])}"
            except:
                error_msg += f" - {response.text[:200]}"
            print(f"Keywords Everywhere API error: {error_msg}")
            return {'success': False, 'error': error_msg, 'source': 'keywords_everywhere'}
    except Exception as e:
        print(f"Keywords Everywhere exception: {e}")
        return {'success': False, 'error': str(e), 'source': 'keywords_everywhere'}

def get_keywords_everywhere_related(keyword):
    try:
        if not KEYWORDS_EVERYWHERE_API_KEY:
            return {'success': False, 'error': 'Keywords Everywhere API key not configured. Please add KEYWORDS_EVERYWHERE_API_KEY to Railway.', 'source': 'keywords_everywhere'}

        url = "https://api.keywordseverywhere.com/v1/get_related_keywords"
        headers = {
            "Authorization": f"Bearer {KEYWORDS_EVERYWHERE_API_KEY}",
            "Accept": "application/json"
        }
        data = [
            ("country", "us"),
            ("currency", "usd"),
            ("kw[]", keyword)
        ]

        response = requests.post(url, headers=headers, data=data, timeout=30)

        if response.status_code == 200:
            result = response.json()
            return {'success': True, 'related': result.get('data', []), 'source': 'keywords_everywhere'}
        elif response.status_code == 401:
            return {'success': False, 'error': 'Keywords Everywhere API key is invalid or expired. Please update KEYWORDS_EVERYWHERE_API_KEY in Railway.', 'source': 'keywords_everywhere'}
        else:
            error_msg = f"Keywords Everywhere API error: {response.status_code}"
            try:
                error_detail = response.json()
                error_msg += f" - {error_detail.get('message', response.text[:200])}"
            except:
                error_msg += f" - {response.text[:200]}"
            return {'success': False, 'error': error_msg, 'source': 'keywords_everywhere'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'source': 'keywords_everywhere'}

def get_serpapi_youtube_data(keyword):
    try:
        if not SERPAPI_API_KEY:
            return {'success': False, 'error': 'SerpAPI key not configured', 'source': 'serpapi'}

        url = "https://serpapi.com/search.json"
        params = {"engine": "youtube", "search_query": keyword, "api_key": SERPAPI_API_KEY}

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            videos = data.get('video_results', [])

            total_views = 0
            view_counts = []
            channels = {}

            for video in videos[:10]:
                views = parse_view_count(video.get('views', '0'))
                total_views += views
                view_counts.append(views)
                channel = video.get('channel', {}).get('name', 'Unknown')
                if channel not in channels:
                    channels[channel] = 0
                channels[channel] += views

            avg_views = total_views // len(videos) if videos else 0
            pattern = determine_view_pattern(view_counts) if view_counts else 'no_data'
            top_channel = max(channels.items(), key=lambda x: x[1])[0] if channels else 'Unknown'

            return {
                'success': True, 'total_views': total_views, 'avg_views': avg_views,
                'video_count': len(videos), 'top_channel': top_channel,
                'view_pattern': pattern, 'videos': videos[:5], 'source': 'serpapi'
            }
        else:
            return {'success': False, 'error': f"SerpAPI error: {response.status_code}", 'source': 'serpapi'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'source': 'serpapi'}

def get_serpapi_autocomplete(keyword):
    """
    Get keyword suggestions from Google Autocomplete via SerpAPI.
    Returns up to 10 keyword suggestions.
    """
    try:
        if not SERPAPI_API_KEY:
            return {'success': False, 'error': 'SerpAPI key not configured', 'source': 'serpapi'}

        url = "https://serpapi.com/search.json"
        params = {
            "engine": "google_autocomplete",
            "q": keyword,
            "api_key": SERPAPI_API_KEY,
            "gl": "us",
            "hl": "en"
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            suggestions = data.get('suggestions', [])

            keywords = []
            for s in suggestions:
                kw = s.get('value', '')
                if kw and kw.lower() != keyword.lower():
                    keywords.append({
                        'keyword': kw,
                        'type': s.get('type', 'suggestion'),
                        'source': 'google_autocomplete'
                    })

            return {'success': True, 'suggestions': keywords, 'source': 'serpapi_autocomplete'}
        else:
            return {'success': False, 'error': f"SerpAPI Autocomplete error: {response.status_code}", 'source': 'serpapi'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'source': 'serpapi'}

def _analyze_seasonal_patterns(timeline_data):
    """Analyze timeline data to detect seasonal patterns.
    Groups data points by month across years, finds peaks/lows, and recommends publish windows."""
    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    month_buckets = {i: [] for i in range(12)}  # 0=Jan, 11=Dec

    for point in timeline_data:
        date_str = point.get('date', '')
        values = point.get('values', [{}])
        interest = values[0].get('extracted_value', 0) if values else 0

        # Parse month from date string (e.g. "Jan 1 – 7, 2024" or "Jan 2024")
        for i, name in enumerate(month_names):
            if name in date_str:
                month_buckets[i].append(interest)
                break

    # Calculate monthly averages
    monthly_averages = {}
    for i in range(12):
        if month_buckets[i]:
            monthly_averages[month_names[i]] = round(sum(month_buckets[i]) / len(month_buckets[i]), 1)
        else:
            monthly_averages[month_names[i]] = 0

    avg_values = [v for v in monthly_averages.values() if v > 0]
    if not avg_values:
        return {'peak_months': None, 'low_months': None, 'seasonality_score': 0,
                'publish_window': None, 'monthly_averages': monthly_averages}

    overall_avg = sum(avg_values) / len(avg_values)

    # Seasonality score: coefficient of variation (0-100)
    if overall_avg > 0:
        variance = sum((v - overall_avg) ** 2 for v in avg_values) / len(avg_values)
        std_dev = variance ** 0.5
        cv = (std_dev / overall_avg) * 100
        seasonality_score = min(100, round(cv * 2.5))  # Scale: CV of 40% = score 100
    else:
        seasonality_score = 0

    # Find peak months (>= 115% of average) and low months (<= 85% of average)
    peak_threshold = overall_avg * 1.15
    low_threshold = overall_avg * 0.85

    peak_months = [month_names[i] for i in range(12) if monthly_averages[month_names[i]] >= peak_threshold]
    low_months = [month_names[i] for i in range(12) if 0 < monthly_averages[month_names[i]] <= low_threshold]

    # Determine publish window: 1-2 months before earliest peak
    publish_window = None
    if peak_months:
        peak_indices = [month_names.index(m) for m in peak_months]
        # Find the start of the biggest peak cluster
        earliest_peak = min(peak_indices)
        publish_month_idx = (earliest_peak - 2) % 12  # 2 months before peak
        publish_end_idx = (earliest_peak - 1) % 12    # 1 month before peak
        publish_window = f"{month_names[publish_month_idx]}-{month_names[publish_end_idx]}"

    return {
        'peak_months': ','.join(peak_months) if peak_months else None,
        'low_months': ','.join(low_months) if low_months else None,
        'seasonality_score': seasonality_score,
        'publish_window': publish_window,
        'monthly_averages': monthly_averages
    }

def get_serpapi_google_trends(keyword):
    """
    Get Google Trends data via SerpAPI.
    Returns interest over time, trend direction, and seasonal patterns.
    Uses 5-year timeframe for seasonal analysis.
    """
    try:
        if not SERPAPI_API_KEY:
            return {'success': False, 'error': 'SerpAPI key not configured', 'source': 'serpapi'}

        url = "https://serpapi.com/search.json"
        params = {
            "engine": "google_trends",
            "q": keyword,
            "api_key": SERPAPI_API_KEY,
            "geo": "US",
            "data_type": "TIMESERIES",
            "date": "today 5-y"  # 5 years for seasonal pattern detection
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()

            # Get interest over time data
            interest_over_time = data.get('interest_over_time', {})
            timeline_data = interest_over_time.get('timeline_data', [])

            # Calculate trend direction (compare recent 3 months vs same period last year)
            trend = 'stable'
            trend_change = 0
            if len(timeline_data) >= 8:
                # With 5-year weekly data, last ~13 points ≈ 3 months, 52 points back ≈ 1 year ago
                recent = timeline_data[-13:]  # Last ~3 months
                # Same period last year (roughly)
                year_ago_start = max(0, len(timeline_data) - 65)
                year_ago_end = max(0, len(timeline_data) - 52)
                older = timeline_data[year_ago_start:year_ago_end] if year_ago_end > year_ago_start else timeline_data[:13]

                recent_avg = sum(d.get('values', [{}])[0].get('extracted_value', 0) for d in recent) / len(recent)
                older_avg = sum(d.get('values', [{}])[0].get('extracted_value', 0) for d in older) / len(older) if older else 0

                if older_avg > 0:
                    trend_change = ((recent_avg - older_avg) / older_avg) * 100

                if trend_change > 20:
                    trend = 'rising'
                elif trend_change < -20:
                    trend = 'declining'
                else:
                    trend = 'stable'

            # Get current interest score (0-100)
            current_interest = 0
            if timeline_data:
                last_point = timeline_data[-1]
                values = last_point.get('values', [{}])
                if values:
                    current_interest = values[0].get('extracted_value', 0)

            # Analyze seasonal patterns from 5-year data
            seasonal = _analyze_seasonal_patterns(timeline_data)

            return {
                'success': True,
                'trend': trend,
                'trend_change_pct': round(trend_change, 1),
                'current_interest': current_interest,
                'data_points': len(timeline_data),
                'peak_months': seasonal['peak_months'],
                'low_months': seasonal['low_months'],
                'seasonality_score': seasonal['seasonality_score'],
                'publish_window': seasonal['publish_window'],
                'monthly_averages': seasonal['monthly_averages'],
                'source': 'google_trends'
            }
        else:
            return {'success': False, 'error': f"SerpAPI Trends error: {response.status_code}", 'source': 'serpapi'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'source': 'serpapi'}

def get_serpapi_related_queries(keyword):
    """
    Get related queries from Google Trends via SerpAPI.
    Returns rising and top related keywords.
    """
    try:
        if not SERPAPI_API_KEY:
            return {'success': False, 'error': 'SerpAPI key not configured', 'source': 'serpapi'}

        url = "https://serpapi.com/search.json"
        params = {
            "engine": "google_trends",
            "q": keyword,
            "api_key": SERPAPI_API_KEY,
            "geo": "US",
            "data_type": "RELATED_QUERIES"
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()

            related_queries = data.get('related_queries', {})
            rising = related_queries.get('rising', [])
            top = related_queries.get('top', [])

            keywords = []

            # Add rising queries (high potential)
            for q in rising[:10]:
                keywords.append({
                    'keyword': q.get('query', ''),
                    'trend_type': 'rising',
                    'value': q.get('extracted_value', q.get('value', 'Breakout')),
                    'source': 'google_trends_related'
                })

            # Add top queries
            for q in top[:10]:
                keywords.append({
                    'keyword': q.get('query', ''),
                    'trend_type': 'top',
                    'value': q.get('extracted_value', q.get('value', 0)),
                    'source': 'google_trends_related'
                })

            return {
                'success': True,
                'related': keywords,
                'rising_count': len(rising),
                'top_count': len(top),
                'source': 'google_trends_related'
            }
        else:
            return {'success': False, 'error': f"SerpAPI Related error: {response.status_code}", 'source': 'serpapi'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'source': 'serpapi'}

def get_serpapi_keyword_data(keyword):
    """
    Combined SerpAPI keyword research - gets autocomplete, trends, and related queries.
    Use this as an alternative to Keywords Everywhere.
    """
    results = {
        'keyword': keyword,
        'success': True,
        'suggestions': [],
        'related': [],
        'trend': 'unknown',
        'trend_change_pct': 0,
        'current_interest': 0,
        'errors': []
    }

    # Get autocomplete suggestions
    autocomplete = get_serpapi_autocomplete(keyword)
    if autocomplete.get('success'):
        results['suggestions'] = autocomplete.get('suggestions', [])
    else:
        results['errors'].append(autocomplete.get('error', 'Autocomplete failed'))

    # Get trend data
    trends = get_serpapi_google_trends(keyword)
    if trends.get('success'):
        results['trend'] = trends.get('trend', 'unknown')
        results['trend_change_pct'] = trends.get('trend_change_pct', 0)
        results['current_interest'] = trends.get('current_interest', 0)
    else:
        results['errors'].append(trends.get('error', 'Trends failed'))

    # Get related queries
    related = get_serpapi_related_queries(keyword)
    if related.get('success'):
        results['related'] = related.get('related', [])
    else:
        results['errors'].append(related.get('error', 'Related queries failed'))

    return results

def parse_view_count(view_string):
    if not view_string:
        return 0
    view_string = str(view_string).lower().replace(',', '').replace(' views', '').strip()
    try:
        if 'k' in view_string:
            return int(float(view_string.replace('k', '')) * 1000)
        elif 'm' in view_string:
            return int(float(view_string.replace('m', '')) * 1000000)
        elif 'b' in view_string:
            return int(float(view_string.replace('b', '')) * 1000000000)
        else:
            return int(float(view_string))
    except:
        return 0

def determine_view_pattern(view_counts):
    if not view_counts or len(view_counts) < 3:
        return 'no_data'
    total = sum(view_counts)
    if total == 0:
        return 'no_data'
    top_share = view_counts[0] / total
    top3_share = sum(view_counts[:3]) / total
    if top_share > 0.5:
        return 'winner_take_all'
    elif top3_share > 0.7:
        return 'top_heavy'
    else:
        return 'distributed'

def calculate_opportunity_score(keyword_data, yt_data):
    score = 50
    volume = keyword_data.get('volume', 0)
    if volume > 10000: score += 20
    elif volume > 5000: score += 15
    elif volume > 1000: score += 10
    elif volume > 500: score += 5

    pattern = yt_data.get('view_pattern', 'no_data')
    if pattern == 'distributed': score += 30
    elif pattern == 'top_heavy': score += 15
    elif pattern == 'winner_take_all': score += 5

    avg_views = yt_data.get('avg_views', 0)
    if avg_views > 100000: score += 20
    elif avg_views > 50000: score += 15
    elif avg_views > 10000: score += 10
    elif avg_views > 1000: score += 5

    difficulty = keyword_data.get('keyword_difficulty', 50)
    if difficulty > 70: score -= 20
    elif difficulty > 50: score -= 10
    elif difficulty > 30: score -= 5

    return min(100, max(0, score))

def determine_tier(score):
    if score >= 75: return 'A - Top Priority'
    elif score >= 55: return 'B - High Value'
    elif score >= 35: return 'C - Growth'
    else: return 'D - Nurture'

def classify_keyword_type(keyword):
    """Classify keyword type based on patterns - calibrated from real revenue data"""
    kw_lower = keyword.lower()
    if ' vs ' in kw_lower:
        return 'comparison'
    elif 'review' in kw_lower or 'reviews' in kw_lower:
        return 'review'
    elif kw_lower.startswith('best ') or ' best ' in kw_lower:
        return 'best_of'
    elif any(term in kw_lower for term in ['coupon', 'discount', 'code', 'deal', 'promo']):
        return 'deal'
    elif any(term in kw_lower for term in ['how to', 'what is', 'why', 'when', 'guide']):
        return 'informational'
    else:
        return 'other'

def estimate_willingness_to_spend(keyword, keyword_type='other', niche='other'):
    """
    Estimate the percentage of searchers willing to pay for a solution.

    This affects revenue potential - keywords where people want FREE solutions
    will convert much worse than keywords where people are ready to buy.

    Returns: float between 0.0 and 1.0 (percentage as decimal)
    """
    kw_lower = keyword.lower()

    # Start with base willingness by keyword type
    base_willingness = {
        'deal': 0.95,        # Looking for coupon = definitely buying
        'comparison': 0.80,  # Comparing X vs Y = close to decision
        'review': 0.70,      # Researching specific product = likely buying
        'best_of': 0.60,     # Looking for recommendations = considering purchase
        'informational': 0.25,  # Just learning = low intent
        'other': 0.50
    }
    willingness = base_willingness.get(keyword_type, 0.50)

    # NEGATIVE signals - reduce willingness significantly
    if 'free' in kw_lower:
        willingness *= 0.15  # "best free vpn" = mostly want free
    if 'cheap' in kw_lower or 'budget' in kw_lower or 'affordable' in kw_lower:
        willingness *= 0.60  # Price sensitive but willing to pay something
    if any(term in kw_lower for term in ['hack', 'hacked', 'crack', 'cracked', 'pirate', 'torrent']):
        willingness *= 0.05  # Want to steal it
    if any(term in kw_lower for term in ['not working', 'error', 'problem', 'issue', 'fix', 'broken']):
        willingness *= 0.20  # Support query, want free help
    if any(term in kw_lower for term in ['alternative to', 'alternatives', 'like']):
        willingness *= 0.70  # Looking for options, might want free
    if any(term in kw_lower for term in ['cancel', 'refund', 'unsubscribe', 'delete account']):
        willingness *= 0.10  # Trying to leave, not buy
    if any(term in kw_lower for term in ['what is', 'how does', 'meaning', 'definition']):
        willingness *= 0.30  # Educational, early stage

    # POSITIVE signals - increase willingness
    if any(term in kw_lower for term in ['buy', 'purchase', 'subscribe', 'pricing', 'cost', 'price']):
        willingness = min(0.95, willingness * 1.5)  # Ready to buy
    if any(term in kw_lower for term in ['coupon', 'discount', 'promo code', 'deal', 'sale']):
        willingness = 0.95  # Actively looking to purchase with discount
    if any(term in kw_lower for term in ['premium', 'pro', 'enterprise', 'business']):
        willingness = min(0.90, willingness * 1.3)  # Looking for paid tier
    if 'worth it' in kw_lower or 'is it worth' in kw_lower:
        willingness = min(0.85, willingness * 1.2)  # Evaluating purchase

    # Niche adjustments - some niches have higher buyer intent
    niche_multipliers = {
        'vpn': 1.1,           # People expect to pay for VPN
        'mattress': 1.2,      # Definitely buying a mattress
        'llc_formation': 1.3, # Business expense, will pay
        'web_hosting': 1.1,   # Expect to pay
        'antivirus': 0.9,     # Lots of free options available
        'parental_control': 1.0,
        'identity_theft': 1.1,
        'pet_tech': 1.0,
    }
    niche_mult = niche_multipliers.get(niche, 1.0)
    willingness *= niche_mult

    # Cap between 5% and 95%
    return round(max(0.05, min(0.95, willingness)), 2)

def suggest_ideal_brand(keyword, niche='other'):
    """
    Suggest the ideal brand/product that people searching this keyword would buy.
    Based on niche, keyword signals, and market leaders.
    """
    kw_lower = keyword.lower()

    # Top brands by niche (ordered by typical affiliate commission & conversion)
    NICHE_BRANDS = {
        'vpn': {
            'default': 'NordVPN',
            'brands': {
                'streaming': 'ExpressVPN',
                'gaming': 'NordVPN',
                'cheap': 'Surfshark',
                'budget': 'Surfshark',
                'free': 'ProtonVPN',
                'privacy': 'ExpressVPN',
                'torrenting': 'NordVPN',
                'china': 'ExpressVPN',
                'business': 'NordVPN Teams',
                'router': 'ExpressVPN',
                'firestick': 'NordVPN',
                'android': 'NordVPN',
                'iphone': 'ExpressVPN',
                'mac': 'ExpressVPN',
                'windows': 'NordVPN',
            }
        },
        'mattress': {
            'default': 'Helix',
            'brands': {
                'back pain': 'Saatva',
                'side sleeper': 'Helix Midnight',
                'stomach': 'WinkBed',
                'cooling': 'Purple',
                'memory foam': 'Nectar',
                'hybrid': 'Helix',
                'luxury': 'Saatva',
                'budget': 'Nectar',
                'cheap': 'Nectar',
                'couples': 'Helix',
                'heavy': 'WinkBed Plus',
                'firm': 'Saatva',
                'soft': 'Layla',
            }
        },
        'antivirus': {
            'default': 'Norton 360',
            'brands': {
                'free': 'Avast',
                'mac': 'Intego',
                'windows': 'Bitdefender',
                'gaming': 'Norton 360',
                'business': 'Bitdefender GravityZone',
                'family': 'Norton 360 Deluxe',
                'lightweight': 'ESET',
                'android': 'Bitdefender Mobile',
            }
        },
        'identity_theft': {
            'default': 'Aura',
            'brands': {
                'family': 'Aura Family',
                'credit': 'IdentityGuard',
                'comprehensive': 'LifeLock',
                'budget': 'Identity Defense',
                'senior': 'Aura',
            }
        },
        'parental_control': {
            'default': 'Qustodio',
            'brands': {
                'iphone': 'Bark',
                'android': 'Qustodio',
                'screen time': 'OurPact',
                'monitoring': 'Bark',
                'location': 'Life360',
                'router': 'Circle',
                'free': 'Google Family Link',
            }
        },
        'web_hosting': {
            'default': 'SiteGround',
            'brands': {
                'wordpress': 'SiteGround',
                'cheap': 'Hostinger',
                'budget': 'Hostinger',
                'beginner': 'Bluehost',
                'ecommerce': 'Cloudways',
                'woocommerce': 'SiteGround',
                'vps': 'Cloudways',
                'managed': 'Kinsta',
                'agency': 'Cloudways',
                'fast': 'Kinsta',
            }
        },
        'email_marketing': {
            'default': 'ConvertKit',
            'brands': {
                'beginner': 'Mailchimp',
                'free': 'Mailchimp',
                'blogger': 'ConvertKit',
                'ecommerce': 'Klaviyo',
                'automation': 'ActiveCampaign',
                'cheap': 'MailerLite',
                'enterprise': 'HubSpot',
            }
        },
        'home_security': {
            'default': 'SimpliSafe',
            'brands': {
                'diy': 'SimpliSafe',
                'professional': 'ADT',
                'camera': 'Ring',
                'doorbell': 'Ring',
                'smart home': 'Vivint',
                'no contract': 'SimpliSafe',
                'apartment': 'Ring',
                'budget': 'Wyze',
            }
        },
        'pet_tech': {
            'default': 'Fi Collar',
            'brands': {
                'gps': 'Fi Collar',
                'tracker': 'Fi Collar',
                'camera': 'Furbo',
                'fence': 'SpotOn',
                'training': 'SpotOn',
                'feeder': 'Petlibro',
                'dog': 'Fi Collar',
                'cat': 'Tractive',
            }
        },
        'llc_formation': {
            'default': 'ZenBusiness',
            'brands': {
                'cheap': 'IncFile',
                'budget': 'IncFile',
                'fast': 'ZenBusiness',
                'registered agent': 'Northwest',
                'premium': 'LegalZoom',
                'nonprofit': 'LegalZoom',
                'comprehensive': 'ZenBusiness',
            }
        },
        'data_broker_removal': {
            'default': 'DeleteMe',
            'brands': {
                'comprehensive': 'DeleteMe',
                'privacy': 'DeleteMe',
                'automated': 'Incogni',
                'cheap': 'Incogni',
                'bundle': 'Aura',
            }
        },
    }

    # Check if a specific brand is mentioned in the keyword
    all_brands = [
        'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'protonvpn', 'pia',
        'norton', 'bitdefender', 'mcafee', 'kaspersky', 'avast', 'avg',
        'purple', 'casper', 'nectar', 'saatva', 'helix', 'tempurpedic',
        'aura', 'lifelock', 'identityguard',
        'qustodio', 'bark', 'ourpact', 'life360',
        'siteground', 'bluehost', 'hostinger', 'cloudways', 'kinsta',
        'convertkit', 'mailchimp', 'klaviyo', 'activecampaign',
        'simplisafe', 'adt', 'ring', 'vivint',
        'zenbusiness', 'incfile', 'legalzoom', 'northwest',
        'deleteme', 'incogni',
    ]

    # If keyword mentions a specific brand, that's likely what they'll buy
    for brand in all_brands:
        if brand in kw_lower:
            # Return properly capitalized brand name
            brand_names = {
                'nordvpn': 'NordVPN', 'expressvpn': 'ExpressVPN', 'surfshark': 'Surfshark',
                'cyberghost': 'CyberGhost', 'protonvpn': 'ProtonVPN', 'pia': 'Private Internet Access',
                'norton': 'Norton 360', 'bitdefender': 'Bitdefender', 'mcafee': 'McAfee',
                'kaspersky': 'Kaspersky', 'avast': 'Avast', 'avg': 'AVG',
                'purple': 'Purple', 'casper': 'Casper', 'nectar': 'Nectar',
                'saatva': 'Saatva', 'helix': 'Helix', 'tempurpedic': 'Tempur-Pedic',
                'aura': 'Aura', 'lifelock': 'LifeLock', 'identityguard': 'IdentityGuard',
                'qustodio': 'Qustodio', 'bark': 'Bark', 'ourpact': 'OurPact', 'life360': 'Life360',
                'siteground': 'SiteGround', 'bluehost': 'Bluehost', 'hostinger': 'Hostinger',
                'cloudways': 'Cloudways', 'kinsta': 'Kinsta',
                'convertkit': 'ConvertKit', 'mailchimp': 'Mailchimp', 'klaviyo': 'Klaviyo',
                'activecampaign': 'ActiveCampaign',
                'simplisafe': 'SimpliSafe', 'adt': 'ADT', 'ring': 'Ring', 'vivint': 'Vivint',
                'zenbusiness': 'ZenBusiness', 'incfile': 'IncFile', 'legalzoom': 'LegalZoom',
                'northwest': 'Northwest', 'deleteme': 'DeleteMe', 'incogni': 'Incogni',
            }
            return brand_names.get(brand, brand.title())

    # Look up niche-specific recommendations
    if niche in NICHE_BRANDS:
        niche_data = NICHE_BRANDS[niche]
        # Check for keyword signals
        for signal, brand in niche_data.get('brands', {}).items():
            if signal in kw_lower:
                return brand
        # Return default for niche
        return niche_data['default']

    # Generic fallback
    return '-'

def estimate_revenue_potential(keyword_data, yt_data, niche='general', keyword=''):
    """
    CALIBRATED REVENUE MODEL - Based on ALL-TIME revenue data (356 keywords)

    Key insights from real data:
    - Median keyword earns ~$36/month (all-time avg)
    - 75th percentile: ~$156/month
    - 90th percentile: ~$659/month
    - Top performers: $10K-20K/month

    EPV by keyword type (median values from all-time data):
    - Deal: $1.18 (75th pct: $4.69)
    - Comparison: $0.53 (75th pct: $1.27)
    - Review: $0.31 (75th pct: $0.72)
    - Best_of: $0.16 (75th pct: $0.42)
    """
    volume = keyword_data.get('volume', 0)
    pattern = yt_data.get('view_pattern', 'no_data')
    video_count = yt_data.get('video_count', 0)

    # EPV (Earnings Per Visitor) by keyword type - CALIBRATED FROM ALL-TIME DATA
    keyword_type = classify_keyword_type(keyword)
    epv_by_type = {
        'deal': 1.18,         # Median from all-time data (356 kws)
        'comparison': 0.53,   # Median from all-time data
        'review': 0.31,       # Median from all-time data
        'best_of': 0.16,      # Median from all-time data
        'informational': 0.31,
        'other': 0.17         # Median from all-time data
    }
    base_epv = epv_by_type.get(keyword_type, 0.25)

    # Traffic capture rate based on competition (view pattern)
    capture_rates = {
        'distributed': 0.15,      # Low competition - can capture 15%
        'top_heavy': 0.08,        # Medium competition - 8%
        'winner_take_all': 0.03,  # High competition - only 3%
        'no_data': 0.10           # Unknown - assume moderate
    }
    capture_rate = capture_rates.get(pattern, 0.10)

    # Adjust capture rate based on video count
    if video_count < 5:
        capture_rate *= 1.5  # Low competition bonus
    elif video_count > 20:
        capture_rate *= 0.7  # High competition penalty

    # Niche EPV multiplier - some niches convert better
    niche_multipliers = {
        'vpn': 1.5,
        'identity_theft': 1.4,
        'data_broker_removal': 1.3,
        'antivirus': 1.2,
        'web_hosting': 1.3,
        'email_marketing': 1.2,
        'parental_control': 1.1,
        'home_security': 1.0,
        'pet_tech': 1.0,
        'general': 1.0
    }
    niche_mult = niche_multipliers.get(niche, 1.0)

    # Calculate revenue estimates
    monthly_traffic = volume * capture_rate
    adjusted_epv = base_epv * niche_mult

    conservative = monthly_traffic * adjusted_epv * 0.5  # 50% of estimate
    moderate = monthly_traffic * adjusted_epv            # Full estimate
    optimistic = monthly_traffic * adjusted_epv * 1.8    # 180% of estimate

    return {
        'conservative': round(conservative, 2),
        'moderate': round(moderate, 2),
        'optimistic': round(optimistic, 2),
        'keyword_type': keyword_type,
        'epv': round(adjusted_epv, 2),
        'capture_rate': round(capture_rate * 100, 1),
        'estimated_traffic': round(monthly_traffic, 0)
    }

# ============================================
# ROUTES
# ============================================

@app.route('/')
@login_required
def index():
    user = get_current_user()
    return render_template('index.html', user=user)

@app.route('/api/keywords/refresh', methods=['POST'])
@login_required
def refresh_keywords():
    """Reload keywords from DB into memory. Also imports tracking keywords if missing."""
    global KEYWORDS
    try:
        ensure_tracking_keywords_in_master()
        KEYWORDS = load_keywords()
        return jsonify({'success': True, 'count': len(KEYWORDS), 'message': f'Reloaded {len(KEYWORDS)} keywords from database'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/keywords')
@login_required
@cache_response('keywords', ttl_seconds=300)  # 5 min cache
def get_keywords():
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'

    # Try to load enrichment data from DB; gracefully degrade if DB is unreachable
    labels = {}
    yt_data = {}
    vote_data = {}
    user_votes = {}
    comment_counts = {}
    additions = {}
    trends_data = {}
    db_available = False

    try:
        conn = get_db()
        c = conn.cursor()

        # Get labels (with attribution)
        c.execute('SELECT keyword, label, is_favorite, notes, label_updated_by, favorite_updated_by, notes_updated_by FROM keyword_labels')
        for row in c.fetchall():
            labels[row[0]] = {
                'label': row[1], 'favorite': bool(row[2]), 'notes': row[3],
                'labelBy': row[4] or '', 'favoriteBy': row[5] or '', 'notesBy': row[6] or ''
            }

        # Get YT data from database (collected via cron)
        c.execute('SELECT keyword, yt_avg_views, yt_view_pattern, yt_top_video_title, yt_top_video_views, yt_top_video_channel FROM keyword_yt_data')
        yt_data = {row[0].lower(): {
            'ytViews': row[1],
            'ytPattern': row[2],
            'ytTopVideo': row[3],
            'ytTopViews': row[4],
            'ytTopChannel': row[5]
        } for row in c.fetchall()}

        # Get vote counts per keyword
        c.execute('''
            SELECT keyword,
                   COALESCE(SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END), 0) as upvotes,
                   COALESCE(SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END), 0) as downvotes
            FROM keyword_votes GROUP BY keyword
        ''')
        vote_data = {row[0]: {'upvotes': row[1], 'downvotes': row[2], 'score': row[1] - row[2]} for row in c.fetchall()}

        # Get current user's votes
        c.execute('SELECT keyword, vote FROM keyword_votes WHERE user_email = %s', (user_email,))
        user_votes = {row[0]: row[1] for row in c.fetchall()}

        # Get comment counts per keyword
        c.execute('SELECT keyword, COUNT(*) FROM keyword_comments GROUP BY keyword')
        comment_counts = {row[0]: row[1] for row in c.fetchall()}

        # Get who added each keyword (with timestamp)
        c.execute('SELECT keyword, user_name, user_email, source, created_at FROM keyword_additions')
        for row in c.fetchall():
            if row[0] not in additions:
                additions[row[0]] = []
            additions[row[0]].append({'name': row[1] or row[2], 'source': row[3], 'added_at': row[4].isoformat() if row[4] else None})

        # Use in-memory trends cache (no DB query needed)
        trends_data = TRENDS_CACHE

        release_db(conn)
        db_available = True
    except Exception as db_err:
        print(f"[API/keywords] DB unavailable, serving {len(KEYWORDS)} keywords from memory: {db_err}")

    result = []
    for k in KEYWORDS:
        kw = k.copy()

        # Add labels
        label_data = labels.get(k['keyword'], {'label': 'none', 'favorite': False, 'notes': '', 'labelBy': '', 'favoriteBy': '', 'notesBy': ''})
        kw['label'] = label_data['label']
        kw['favorite'] = label_data['favorite']
        kw['notes'] = label_data['notes']
        kw['labelBy'] = label_data['labelBy']
        kw['favoriteBy'] = label_data['favoriteBy']
        kw['notesBy'] = label_data['notesBy']

        # Merge YT data from database if CSV data is missing
        keyword_lower = k['keyword'].lower()
        if keyword_lower in yt_data and (not kw.get('ytViews') or kw.get('ytViews') == 0):
            db_yt = yt_data[keyword_lower]
            kw['ytViews'] = db_yt['ytViews'] or 0
            kw['ytPattern'] = db_yt['ytPattern'] or 'no_data'
            kw['ytTopVideo'] = db_yt.get('ytTopVideo', '')
            kw['ytTopViews'] = db_yt.get('ytTopViews', 0)
            kw['ytTopChannel'] = db_yt.get('ytTopChannel', '')

        # Calculate willingness to spend
        keyword_type = classify_keyword_type(k['keyword'])
        willingness = estimate_willingness_to_spend(k['keyword'], keyword_type, k.get('niche', 'other'))
        kw['willingness'] = willingness

        # Adjust revenue by willingness (original revenue assumed 100% willingness)
        kw['revenue_original'] = kw.get('revenue', 0)
        kw['revenue'] = round(kw.get('revenue', 0) * willingness, 2)

        # Suggest ideal brand for this keyword
        kw['idealBrand'] = suggest_ideal_brand(k['keyword'], k.get('niche', 'other'))

        # Add vote data
        kw_votes = vote_data.get(k['keyword'], {'upvotes': 0, 'downvotes': 0, 'score': 0})
        kw['upvotes'] = kw_votes['upvotes']
        kw['downvotes'] = kw_votes['downvotes']
        kw['voteScore'] = kw_votes['score']
        kw['userVote'] = user_votes.get(k['keyword'], 0)

        # Add comment count
        kw['commentCount'] = comment_counts.get(k['keyword'], 0)

        # Add Google Trends data (including seasonal patterns)
        kw_trend = trends_data.get(keyword_lower, {'trend': 'unknown', 'trendChange': 0, 'trendInterest': 0, 'peakMonths': None, 'seasonalityScore': 0, 'publishWindow': None, 'trendUpdated': None})
        kw['trend'] = kw_trend['trend']
        kw['trendChange'] = kw_trend['trendChange']
        kw['trendInterest'] = kw_trend['trendInterest']
        kw['peakMonths'] = kw_trend.get('peakMonths')
        kw['seasonalityScore'] = kw_trend.get('seasonalityScore', 0)
        kw['publishWindow'] = kw_trend.get('publishWindow')
        kw['trendUpdated'] = kw_trend.get('trendUpdated')

        # Add who added this keyword
        kw_additions = additions.get(k['keyword'], [])
        kw['addedBy'] = kw_additions
        # Expose most recent addition timestamp for "New" filtering
        if kw_additions:
            dates = [a['added_at'] for a in kw_additions if a.get('added_at')]
            kw['addedAt'] = max(dates) if dates else None
        else:
            kw['addedAt'] = None

        result.append(kw)

    return jsonify(result)

@app.route('/api/stats')
@login_required
def get_stats():
    total = len(KEYWORDS)
    total_revenue = sum(k['revenue'] for k in KEYWORDS)
    a_tier = sum(1 for k in KEYWORDS if 'A -' in k['tier'])
    avg_priority = sum(k['priority'] for k in KEYWORDS) / total if total > 0 else 0

    niches = {}
    for k in KEYWORDS:
        niche = k['niche']
        if niche not in niches:
            niches[niche] = {'count': 0, 'revenue': 0}
        niches[niche]['count'] += 1
        niches[niche]['revenue'] += k['revenue']

    return jsonify({'total': total, 'totalRevenue': total_revenue, 'aTier': a_tier, 'avgPriority': round(avg_priority, 1), 'niches': niches})

@app.route('/api/export')
def export_csv():
    niche = request.args.get('niche', '')
    funnel = request.args.get('funnel', '')
    tier = request.args.get('tier', '')
    pattern = request.args.get('pattern', '')
    search = request.args.get('search', '').lower()

    filtered = KEYWORDS
    if niche: filtered = [k for k in filtered if k['niche'] == niche]
    if funnel: filtered = [k for k in filtered if k['funnel'] == funnel]
    if tier: filtered = [k for k in filtered if k['tier'] == tier]
    if pattern: filtered = [k for k in filtered if k['ytPattern'] == pattern]
    if search: filtered = [k for k in filtered if search in k['keyword'].lower()]

    output = []
    headers = ['keyword', 'niche', 'funnel', 'intent', 'volume', 'commission', 'revenue', 'buyingIntent', 'ytViews', 'ytPattern', 'priority', 'tier', 'competition', 'contentAngle', 'rationale']
    output.append(','.join(headers))
    for k in filtered:
        row = [str(k.get(h, '')).replace(',', ';').replace('"', "'") for h in headers]
        output.append(','.join(row))

    return Response('\n'.join(output), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=filtered_keywords.csv'})

@app.route('/api/test-dataforseo', methods=['POST'])
@login_required
def test_dataforseo():
    """Test endpoint to check DataForSEO API directly"""
    try:
        data = request.get_json()
        keyword = data.get('keyword', 'test keyword').strip()

        # Check if credentials are set
        creds_status = {
            'login_set': bool(DATAFORSEO_LOGIN),
            'password_set': bool(DATAFORSEO_PASSWORD),
            'login_length': len(DATAFORSEO_LOGIN) if DATAFORSEO_LOGIN else 0
        }

        if not DATAFORSEO_LOGIN or not DATAFORSEO_PASSWORD:
            return jsonify({
                'success': False,
                'error': 'DataForSEO credentials not configured',
                'credentials': creds_status
            })

        # Test the API
        result = get_dataforseo_keyword_data([keyword])

        return jsonify({
            'success': result.get('success'),
            'data': result.get('data', []),
            'error': result.get('error'),
            'source': result.get('source'),
            'credentials': creds_status,
            'keyword_tested': keyword
        })

    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/api/serpapi-keywords', methods=['POST'])
@login_required
def serpapi_keyword_research():
    """
    Test endpoint for SerpAPI keyword data.
    Returns autocomplete suggestions, trends, and related queries.
    """
    data = request.get_json()
    keyword = data.get('keyword', '').strip()

    if not keyword:
        return jsonify({'success': False, 'error': 'Keyword is required'}), 400

    # Get comprehensive SerpAPI keyword data
    result = get_serpapi_keyword_data(keyword)

    # Also get YouTube data
    yt_data = get_serpapi_youtube_data(keyword)
    if yt_data.get('success'):
        result['youtube'] = {
            'total_views': yt_data.get('total_views', 0),
            'avg_views': yt_data.get('avg_views', 0),
            'video_count': yt_data.get('video_count', 0),
            'view_pattern': yt_data.get('view_pattern', 'no_data'),
            'top_channel': yt_data.get('top_channel', 'Unknown')
        }

    return jsonify(result)

@app.route('/api/research', methods=['POST'])
@login_required
def research_keyword():
    try:
        data = request.get_json()
        seed_keyword = data.get('keyword', '').strip()
        niche = data.get('niche', 'general')

        if not seed_keyword:
            return jsonify({'success': False, 'error': 'Keyword is required'}), 400

        results = {'seed_keyword': seed_keyword, 'niche': niche, 'timestamp': datetime.now().isoformat(), 'keywords': [], 'errors': []}

        ke_data = get_keyword_data_with_fallback([seed_keyword])
        seed_volume_data = ke_data['data'][0] if ke_data['success'] and ke_data.get('data') else {}
        if not ke_data['success']: results['errors'].append(ke_data.get('error', 'Keyword data API failed'))

        ke_related = get_related_keywords_with_fallback(seed_keyword)
        related_keywords = ke_related.get('related', []) if ke_related['success'] else []
        if not ke_related['success']: results['errors'].append(ke_related.get('error', 'Related keywords failed'))

        yt_data = get_serpapi_youtube_data(seed_keyword)
        if not yt_data['success']:
            results['errors'].append(yt_data.get('error', 'SerpAPI failed'))
            yt_data = {'total_views': 0, 'avg_views': 0, 'video_count': 0, 'view_pattern': 'no_data'}

        # Get trend data from SerpAPI
        trend_data = get_serpapi_google_trends(seed_keyword)

        seed_result = {
            'keyword': seed_keyword,
            'volume': seed_volume_data.get('vol', 0),
            'cpc': seed_volume_data.get('cpc', {}).get('value', 0) if isinstance(seed_volume_data.get('cpc'), dict) else seed_volume_data.get('cpc', 0),
            'competition': seed_volume_data.get('competition', 0),
            'trend': trend_data.get('trend', 'unknown') if trend_data.get('success') else 'unknown',
            'trend_change_pct': trend_data.get('trend_change_pct', 0) if trend_data.get('success') else 0,
            'trend_interest': trend_data.get('current_interest', 0) if trend_data.get('success') else 0,
            'yt_total_views': yt_data.get('total_views', 0),
            'yt_avg_views': yt_data.get('avg_views', 0),
            'yt_video_count': yt_data.get('video_count', 0),
            'yt_view_pattern': yt_data.get('view_pattern', 'no_data'),
            'yt_top_channel': yt_data.get('top_channel', 'Unknown'),
            'source': ke_data.get('source', 'seed'),
            'niche': niche
        }

        seed_result['priority_score'] = calculate_opportunity_score({'volume': seed_result['volume'], 'keyword_difficulty': seed_result['competition'] * 100}, yt_data)
        seed_result['opportunity_tier'] = determine_tier(seed_result['priority_score'])

        # Get calibrated revenue estimates
        revenue_data = estimate_revenue_potential(
            {'volume': seed_result['volume'], 'cpc': seed_result['cpc']},
            yt_data,
            niche,
            keyword=seed_keyword
        )
        seed_result['revenue_potential'] = revenue_data['moderate']
        seed_result['revenue_conservative'] = revenue_data['conservative']
        seed_result['revenue_optimistic'] = revenue_data['optimistic']
        seed_result['keyword_type'] = revenue_data['keyword_type']
        seed_result['epv'] = revenue_data['epv']
        seed_result['capture_rate'] = revenue_data['capture_rate']
        seed_result['estimated_traffic'] = revenue_data['estimated_traffic']

        results['keywords'].append(seed_result)

        if related_keywords:
            related_kw_list = [rk.get('keyword', rk) if isinstance(rk, dict) else rk for rk in related_keywords[:15]]
            related_volume = get_keyword_data_with_fallback(related_kw_list)
            volume_map = {item.get('keyword', ''): item for item in related_volume.get('data', [])} if related_volume['success'] else {}

            for rk in related_keywords[:15]:
                kw = rk.get('keyword', rk) if isinstance(rk, dict) else rk
                if kw == seed_keyword: continue

                vol_data = volume_map.get(kw, {})
                rk_result = {
                    'keyword': kw,
                    'volume': vol_data.get('vol', 0),
                    'cpc': vol_data.get('cpc', {}).get('value', 0) if isinstance(vol_data.get('cpc'), dict) else vol_data.get('cpc', 0),
                    'competition': vol_data.get('competition', 0),
                    'yt_total_views': 0, 'yt_avg_views': 0, 'yt_video_count': 0, 'yt_view_pattern': 'no_data',
                    'source': 'related', 'niche': niche
                }
                rk_result['priority_score'] = calculate_opportunity_score({'volume': rk_result['volume'], 'keyword_difficulty': rk_result['competition'] * 100}, {})
                rk_result['opportunity_tier'] = determine_tier(rk_result['priority_score'])

                # Get calibrated revenue estimates for related keyword
                rk_revenue = estimate_revenue_potential(
                    {'volume': rk_result['volume'], 'cpc': rk_result['cpc']},
                    {},
                    niche,
                    keyword=kw
                )
                rk_result['revenue_potential'] = rk_revenue['moderate']
                rk_result['revenue_conservative'] = rk_revenue['conservative']
                rk_result['revenue_optimistic'] = rk_revenue['optimistic']
                rk_result['keyword_type'] = rk_revenue['keyword_type']
                rk_result['epv'] = rk_revenue['epv']
                rk_result['capture_rate'] = rk_revenue['capture_rate']
                rk_result['estimated_traffic'] = rk_revenue['estimated_traffic']

                results['keywords'].append(rk_result)

        results['keywords'].sort(key=lambda x: x['priority_score'], reverse=True)
        return jsonify(results)

    except Exception as e:
        import traceback
        print(f"Research endpoint error: {e}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/label', methods=['POST'])
@login_required
def set_label():
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    label = data.get('label', 'none')
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'

    valid_labels = ['none', 'interested', 'not_interested', 'maybe', 'researching', 'content_created']
    if label not in valid_labels:
        return jsonify({'success': False, 'error': f'Invalid label'}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO keyword_labels (keyword, label, label_updated_by, updated_at)
                     VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                     ON CONFLICT(keyword) DO UPDATE SET label=%s, label_updated_by=%s, updated_at=CURRENT_TIMESTAMP''',
                  (keyword, label, user_email, label, user_email))
        conn.commit()
        release_db(conn)
        invalidate_cache('keywords', 'smart_picks', 'opportunity_finder')
        return jsonify({'success': True, 'keyword': keyword, 'label': label, 'updatedBy': user_email})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/favorite', methods=['POST'])
@login_required
def toggle_favorite():
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT is_favorite FROM keyword_labels WHERE keyword = %s', (keyword,))
        row = c.fetchone()

        if row:
            new_status = not bool(row[0])
            c.execute('UPDATE keyword_labels SET is_favorite = %s, favorite_updated_by = %s, updated_at = CURRENT_TIMESTAMP WHERE keyword = %s',
                      (new_status, user_email, keyword))
        else:
            new_status = True
            c.execute('INSERT INTO keyword_labels (keyword, is_favorite, favorite_updated_by) VALUES (%s, %s, %s)',
                      (keyword, True, user_email))

        conn.commit()
        release_db(conn)
        invalidate_cache('keywords', 'smart_picks', 'opportunity_finder')
        return jsonify({'success': True, 'keyword': keyword, 'favorite': new_status, 'updatedBy': user_email})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# NOTES ENDPOINT
# ============================================
@app.route('/api/notes', methods=['POST'])
@login_required
def save_notes():
    """Save notes for a keyword, tracked per user"""
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    notes = data.get('notes', '')
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'

    if not keyword:
        return jsonify({'success': False, 'error': 'Keyword is required'}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO keyword_labels (keyword, notes, notes_updated_by, updated_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT(keyword) DO UPDATE SET notes=%s, notes_updated_by=%s, updated_at=CURRENT_TIMESTAMP
        ''', (keyword, notes, user_email, notes, user_email))
        conn.commit()
        release_db(conn)
        return jsonify({'success': True, 'keyword': keyword, 'updatedBy': user_email})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# VOTING ENDPOINTS
# ============================================
@app.route('/api/vote', methods=['POST'])
@login_required
def vote_keyword():
    """Upvote or downvote a keyword. vote=1 for upvote, vote=-1 for downvote, vote=0 to remove vote"""
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    vote = data.get('vote', 0)
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'
    user_name = user.get('name', '') if user else ''

    if not keyword:
        return jsonify({'success': False, 'error': 'Keyword is required'}), 400
    if vote not in [-1, 0, 1]:
        return jsonify({'success': False, 'error': 'Vote must be -1, 0, or 1'}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        if vote == 0:
            # Remove vote
            c.execute('DELETE FROM keyword_votes WHERE keyword = %s AND user_email = %s', (keyword, user_email))
        else:
            c.execute('''
                INSERT INTO keyword_votes (keyword, user_email, user_name, vote, updated_at)
                VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT(keyword, user_email) DO UPDATE SET
                    vote = %s, user_name = %s, updated_at = CURRENT_TIMESTAMP
            ''', (keyword, user_email, user_name, vote, vote, user_name))

        # Return updated vote counts
        c.execute('SELECT COALESCE(SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END), 0) FROM keyword_votes WHERE keyword = %s', (keyword,))
        row = c.fetchone()
        upvotes = row[0]
        downvotes = row[1]

        # Get current user's vote
        c.execute('SELECT vote FROM keyword_votes WHERE keyword = %s AND user_email = %s', (keyword, user_email))
        user_vote_row = c.fetchone()
        user_vote = user_vote_row[0] if user_vote_row else 0

        conn.commit()
        release_db(conn)
        return jsonify({
            'success': True,
            'keyword': keyword,
            'upvotes': upvotes,
            'downvotes': downvotes,
            'score': upvotes - downvotes,
            'user_vote': user_vote
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/votes', methods=['GET'])
@login_required
def get_all_votes():
    """Get vote counts for all keywords and current user's votes"""
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'

    try:
        conn = get_db()
        c = conn.cursor()

        # Get aggregate votes per keyword
        c.execute('''
            SELECT keyword,
                   COALESCE(SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END), 0) as upvotes,
                   COALESCE(SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END), 0) as downvotes
            FROM keyword_votes GROUP BY keyword
        ''')
        vote_counts = {}
        for row in c.fetchall():
            vote_counts[row[0]] = {'upvotes': row[1], 'downvotes': row[2], 'score': row[1] - row[2]}

        # Get current user's votes
        c.execute('SELECT keyword, vote FROM keyword_votes WHERE user_email = %s', (user_email,))
        user_votes = {row[0]: row[1] for row in c.fetchall()}

        # Get voter names per keyword for tooltip
        c.execute('SELECT keyword, user_name, vote FROM keyword_votes ORDER BY keyword')
        voters = {}
        for row in c.fetchall():
            if row[0] not in voters:
                voters[row[0]] = []
            voters[row[0]].append({'name': row[1] or row[0], 'vote': row[2]})

        release_db(conn)
        return jsonify({
            'success': True,
            'vote_counts': vote_counts,
            'user_votes': user_votes,
            'voters': voters
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# COMMENTS ENDPOINTS
# ============================================
@app.route('/api/comments', methods=['GET'])
@login_required
def get_comments():
    """Get all comments, optionally filtered by keyword"""
    keyword = request.args.get('keyword', '').strip()

    try:
        conn = get_db()
        c = conn.cursor()

        if keyword:
            c.execute('''
                SELECT id, keyword, user_email, user_name, comment, created_at, updated_at
                FROM keyword_comments WHERE keyword = %s ORDER BY created_at DESC
            ''', (keyword,))
        else:
            c.execute('''
                SELECT id, keyword, user_email, user_name, comment, created_at, updated_at
                FROM keyword_comments ORDER BY created_at DESC
            ''')

        comments = []
        for row in c.fetchall():
            comments.append({
                'id': row[0],
                'keyword': row[1],
                'user_email': row[2],
                'user_name': row[3],
                'comment': row[4],
                'created_at': row[5],
                'updated_at': row[6]
            })

        release_db(conn)
        return jsonify({'success': True, 'comments': comments})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/comments', methods=['POST'])
@login_required
def add_comment():
    """Add a comment to a keyword"""
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    comment = data.get('comment', '').strip()
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'
    user_name = user.get('name', '') if user else ''

    if not keyword:
        return jsonify({'success': False, 'error': 'Keyword is required'}), 400
    if not comment:
        return jsonify({'success': False, 'error': 'Comment is required'}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO keyword_comments (keyword, user_email, user_name, comment)
            VALUES (%s, %s, %s, %s)
        ''', (keyword, user_email, user_name, comment))
        comment_id = c.lastrowid

        conn.commit()
        release_db(conn)
        return jsonify({
            'success': True,
            'comment': {
                'id': comment_id,
                'keyword': keyword,
                'user_email': user_email,
                'user_name': user_name,
                'comment': comment,
                'created_at': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    """Delete a comment (only by the user who created it)"""
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'

    try:
        conn = get_db()
        c = conn.cursor()

        # Verify ownership
        c.execute('SELECT user_email FROM keyword_comments WHERE id = %s', (comment_id,))
        row = c.fetchone()
        if not row:
            release_db(conn)
            return jsonify({'success': False, 'error': 'Comment not found'}), 404
        if row[0] != user_email:
            release_db(conn)
            return jsonify({'success': False, 'error': 'Not authorized to delete this comment'}), 403

        c.execute('DELETE FROM keyword_comments WHERE id = %s', (comment_id,))
        conn.commit()
        release_db(conn)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# ADD TO LIBRARY (from Research) WITH USER TRACKING
# ============================================
@app.route('/api/library/add', methods=['POST'])
@login_required
def add_to_library():
    """Add a keyword to the library from Research or Channel Analysis, with user tracking"""
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    source = data.get('source', 'manual')
    source_detail = data.get('source_detail', '')
    keyword_data = data.get('keyword_data', {})
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'
    user_name = user.get('name', '') if user else ''

    if not keyword:
        return jsonify({'success': False, 'error': 'Keyword is required'}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        # Track who added it
        c.execute('''
            INSERT INTO keyword_additions (keyword, user_email, user_name, source, source_detail)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT(keyword, user_email) DO UPDATE SET
                source = EXCLUDED.source,
                source_detail = EXCLUDED.source_detail
        ''', (keyword, user_email, user_name, source, source_detail))

        # Add to researched_keywords if it has data
        if keyword_data:
            c.execute('''
                INSERT INTO researched_keywords
                (keyword, seed_keyword, source, search_volume, keyword_difficulty, cpc,
                 yt_avg_views, yt_total_views, yt_video_count, yt_view_pattern,
                 revenue_potential, priority_score, opportunity_tier, niche, funnel_stage)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(keyword, source) DO UPDATE SET
                    search_volume = EXCLUDED.search_volume,
                    revenue_potential = EXCLUDED.revenue_potential,
                    priority_score = EXCLUDED.priority_score,
                    opportunity_tier = EXCLUDED.opportunity_tier,
                    researched_at = CURRENT_TIMESTAMP
            ''', (
                keyword,
                keyword_data.get('seed_keyword', ''),
                source,
                keyword_data.get('volume', 0),
                keyword_data.get('competition', 0),
                keyword_data.get('cpc', 0),
                keyword_data.get('yt_avg_views', 0),
                keyword_data.get('yt_total_views', 0),
                keyword_data.get('yt_video_count', 0),
                keyword_data.get('yt_view_pattern', 'no_data'),
                keyword_data.get('revenue_potential', 0),
                keyword_data.get('priority_score', 0),
                keyword_data.get('opportunity_tier', 'B - High Value'),
                keyword_data.get('niche', 'general'),
                keyword_data.get('funnel_stage', '')
            ))

        # Insert into keywords_master (single source of truth)
        niche = keyword_data.get('niche', 'general') if keyword_data else 'general'
        volume = keyword_data.get('volume', 0) if keyword_data else 0
        c.execute('''
            INSERT INTO keywords_master
            (keyword, niche, volume, yt_avg_monthly_views, yt_view_pattern,
             revenue_potential, priority_score, opportunity_tier,
             added_by_email, added_by_name, source)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(keyword) DO UPDATE SET
                volume = CASE WHEN EXCLUDED.volume > 0 THEN EXCLUDED.volume ELSE keywords_master.volume END,
                updated_at = CURRENT_TIMESTAMP
        ''', (
            keyword, niche, volume,
            keyword_data.get('yt_avg_views', 0) if keyword_data else 0,
            keyword_data.get('yt_view_pattern', '') if keyword_data else '',
            keyword_data.get('revenue_potential', 0) if keyword_data else 0,
            keyword_data.get('priority_score', 0) if keyword_data else 0,
            keyword_data.get('opportunity_tier', 'B - High Value') if keyword_data else 'B - High Value',
            user_email, user_name or user_email, source
        ))

        # Add to in-memory KEYWORDS if not already there
        if not any(k['keyword'].lower() == keyword.lower() for k in KEYWORDS):
            KEYWORDS.append({
                'keyword': keyword, 'niche': niche, 'funnel': '', 'intent': '',
                'volume': volume, 'commission': 0, 'revenue': 0, 'buyingIntent': 0,
                'ytViews': 0, 'ytPattern': '', 'priority': 0, 'tier': 'B - High Value',
                'competition': '', 'contentAngle': '', 'rationale': '',
                'conversionLikelihood': '', 'timeToConvert': '', 'problemType': '',
                'urgencyScore': 0, 'ytTopVideo': '', 'ytTopViews': 0, 'ytTopChannel': '',
                'addedByEmail': user_email, 'addedByName': user_name or user_email, 'source': source,
            })

        # Set label to 'interested' if not already set
        c.execute('''
            INSERT INTO keyword_labels (keyword, label, label_updated_by, notes, updated_at)
            VALUES (%s, 'interested', %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT(keyword) DO UPDATE SET
                label = CASE WHEN keyword_labels.label = 'none' THEN 'interested' ELSE keyword_labels.label END,
                label_updated_by = CASE WHEN keyword_labels.label = 'none' THEN %s ELSE keyword_labels.label_updated_by END,
                updated_at = CURRENT_TIMESTAMP
        ''', (keyword, user_email, f'[Added by {user_name or user_email} from {source}]', user_email))

        conn.commit()
        release_db(conn)
        return jsonify({
            'success': True,
            'keyword': keyword,
            'added_by': user_name or user_email,
            'source': source
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/keywords/add-manual', methods=['POST'])
@login_required
def add_keyword_manual():
    """Add one or more keywords manually from the Library tab"""
    data = request.get_json()
    keywords_input = data.get('keywords', '').strip()
    niche = data.get('niche', 'general')
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'
    user_name = user.get('name', '') if user else ''

    if not keywords_input:
        return jsonify({'success': False, 'error': 'Keywords are required'}), 400

    # Support comma-separated or newline-separated keywords
    raw_keywords = [kw.strip() for kw in keywords_input.replace('\n', ',').split(',') if kw.strip()]

    if not raw_keywords:
        return jsonify({'success': False, 'error': 'No valid keywords provided'}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        added = []
        skipped = []

        for keyword in raw_keywords:
            # Check if already exists
            c.execute('SELECT id FROM keywords_master WHERE keyword = %s', (keyword,))
            if c.fetchone():
                skipped.append(keyword)
                continue

            # Insert into keywords_master
            c.execute('''
                INSERT INTO keywords_master
                (keyword, niche, added_by_email, added_by_name, source)
                VALUES (%s, %s, %s, %s, 'manual')
            ''', (keyword, niche, user_email, user_name or user_email))

            # Track who added it
            c.execute('''
                INSERT INTO keyword_additions (keyword, user_email, user_name, source, source_detail)
                VALUES (%s, %s, %s, 'manual', 'Library tab')
                ON CONFLICT(keyword, user_email) DO UPDATE SET
                    source = 'manual', source_detail = 'Library tab'
            ''', (keyword, user_email, user_name))

            # Set label to 'interested'
            c.execute('''
                INSERT INTO keyword_labels (keyword, label, label_updated_by, updated_at)
                VALUES (%s, 'interested', %s, CURRENT_TIMESTAMP)
                ON CONFLICT(keyword) DO NOTHING
            ''', (keyword, user_email))

            # Add to in-memory KEYWORDS
            KEYWORDS.append({
                'keyword': keyword, 'niche': niche, 'funnel': '', 'intent': '',
                'volume': 0, 'commission': 0, 'revenue': 0, 'buyingIntent': 0,
                'ytViews': 0, 'ytPattern': '', 'priority': 0, 'tier': '',
                'competition': '', 'contentAngle': '', 'rationale': '',
                'conversionLikelihood': '', 'timeToConvert': '', 'problemType': '',
                'urgencyScore': 0, 'ytTopVideo': '', 'ytTopViews': 0, 'ytTopChannel': '',
                'addedByEmail': user_email, 'addedByName': user_name or user_email, 'source': 'manual',
            })

            added.append(keyword)

        conn.commit()
        release_db(conn)

        return jsonify({
            'success': True,
            'added': len(added),
            'skipped': len(skipped),
            'added_keywords': added,
            'skipped_keywords': skipped,
            'message': f'Added {len(added)} keyword(s). {len(skipped)} already existed.',
            'added_by': user_name or user_email
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/keyword/additions', methods=['GET'])
@login_required
def get_keyword_additions():
    """Get who added which keywords"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT keyword, user_email, user_name, source, source_detail, created_at FROM keyword_additions ORDER BY created_at DESC')
        additions = {}
        for row in c.fetchall():
            kw = row[0]
            if kw not in additions:
                additions[kw] = []
            additions[kw].append({
                'user_email': row[1],
                'user_name': row[2],
                'source': row[3],
                'source_detail': row[4],
                'created_at': row[5]
            })
        release_db(conn)
        return jsonify({'success': True, 'additions': additions})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/channel/add-to-library', methods=['POST'])
@login_required
def add_channel_keywords_to_library():
    """Add keywords from channel analysis to the keyword library for further research"""
    data = request.get_json()
    keywords = data.get('keywords', [])
    source_channel = data.get('channel', 'unknown')
    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'
    user_name = user.get('name', '') if user else ''

    if not keywords:
        return jsonify({'success': False, 'error': 'No keywords provided'}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        added = []
        skipped = []

        for kw in keywords:
            keyword = kw.get('keyword', '').strip()
            if not keyword:
                continue

            # Check if keyword already exists
            c.execute('SELECT id FROM researched_keywords WHERE keyword = %s', (keyword,))
            if c.fetchone():
                skipped.append(keyword)
                continue

            # Insert into researched_keywords
            c.execute('''
                INSERT INTO researched_keywords
                (keyword, seed_keyword, source, yt_avg_views, yt_total_views, yt_video_count,
                 yt_view_pattern, revenue_potential, niche, funnel_stage, opportunity_tier)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                keyword,
                source_channel,
                'channel_analysis',
                kw.get('avg_views', 0),
                kw.get('total_views', 0),
                kw.get('count', 0),
                kw.get('view_pattern', 'no_data'),
                kw.get('revenue_potential', 0),
                kw.get('niche', 'general'),
                kw.get('conversion_immediacy', 'medium'),
                'B - High Value'  # Default tier, will be researched
            ))

            # Insert into keywords_master (single source of truth)
            kw_niche = kw.get('niche', 'general')
            c.execute('''
                INSERT INTO keywords_master
                (keyword, niche, yt_avg_monthly_views, yt_view_pattern,
                 revenue_potential, opportunity_tier,
                 added_by_email, added_by_name, source)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(keyword) DO UPDATE SET
                    yt_avg_monthly_views = CASE WHEN EXCLUDED.yt_avg_monthly_views > 0 THEN EXCLUDED.yt_avg_monthly_views ELSE keywords_master.yt_avg_monthly_views END,
                    updated_at = CURRENT_TIMESTAMP
            ''', (
                keyword, kw_niche,
                kw.get('avg_views', 0), kw.get('view_pattern', 'no_data'),
                kw.get('revenue_potential', 0), 'B - High Value',
                user_email, user_name or user_email, 'channel_analysis'
            ))

            # Add to in-memory KEYWORDS if not already there
            if not any(k['keyword'].lower() == keyword.lower() for k in KEYWORDS):
                KEYWORDS.append({
                    'keyword': keyword, 'niche': kw_niche, 'funnel': '', 'intent': '',
                    'volume': 0, 'commission': 0, 'revenue': 0, 'buyingIntent': 0,
                    'ytViews': kw.get('avg_views', 0), 'ytPattern': kw.get('view_pattern', ''),
                    'priority': 0, 'tier': 'B - High Value',
                    'competition': '', 'contentAngle': '', 'rationale': '',
                    'conversionLikelihood': '', 'timeToConvert': '', 'problemType': '',
                    'urgencyScore': 0, 'ytTopVideo': '', 'ytTopViews': 0, 'ytTopChannel': '',
                    'addedByEmail': user_email, 'addedByName': user_name or user_email,
                    'source': 'channel_analysis',
                })

            # Insert/update YouTube data
            c.execute('''
                INSERT INTO keyword_yt_data
                (keyword, yt_avg_views, yt_view_pattern, yt_total_views, yt_video_count)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT(keyword) DO UPDATE SET
                    yt_avg_views = EXCLUDED.yt_avg_views,
                    yt_view_pattern = EXCLUDED.yt_view_pattern,
                    yt_total_views = EXCLUDED.yt_total_views,
                    yt_video_count = EXCLUDED.yt_video_count,
                    updated_at = CURRENT_TIMESTAMP
            ''', (
                keyword,
                kw.get('avg_views', 0),
                kw.get('view_pattern', 'no_data'),
                kw.get('total_views', 0),
                kw.get('count', 0)
            ))

            # Set label to 'researching'
            c.execute('''
                INSERT INTO keyword_labels (keyword, label, label_updated_by, notes, updated_at)
                VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT(keyword) DO UPDATE SET
                    label = CASE WHEN keyword_labels.label = 'none' THEN 'researching' ELSE keyword_labels.label END,
                    label_updated_by = CASE WHEN keyword_labels.label = 'none' THEN %s ELSE keyword_labels.label_updated_by END,
                    notes = COALESCE(keyword_labels.notes, '') || EXCLUDED.notes,
                    updated_at = CURRENT_TIMESTAMP
            ''', (keyword, 'researching', user_email, f' [From channel: {source_channel}]', user_email))

            # Track who added this keyword
            c.execute('''
                INSERT INTO keyword_additions (keyword, user_email, user_name, source, source_detail)
                VALUES (%s, %s, %s, 'channel_analysis', %s)
                ON CONFLICT(keyword, user_email) DO UPDATE SET
                    source = 'channel_analysis',
                    source_detail = EXCLUDED.source_detail
            ''', (keyword, user_email, user_name, source_channel))

            added.append(keyword)

        conn.commit()
        release_db(conn)

        return jsonify({
            'success': True,
            'added': len(added),
            'skipped': len(skipped),
            'added_keywords': added,
            'skipped_keywords': skipped,
            'message': f'Added {len(added)} keywords to library. {len(skipped)} already existed.'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/revenue/analysis')
def analyze_revenue():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT r.keyword, r.video_views, r.affiliate_clicks, r.conversions, r.revenue, k.search_volume, k.yt_avg_views, k.yt_view_pattern FROM revenue_data r LEFT JOIN researched_keywords k ON r.keyword = k.keyword')
        rows = c.fetchall()
        release_db(conn)

        if not rows:
            return jsonify({'success': True, 'message': 'No revenue data yet. Add revenue data to enable pattern analysis.', 'patterns': []})

        analysis = {'total_records': len(rows), 'total_revenue': sum(r[4] for r in rows if r[4]), 'avg_revenue_per_keyword': sum(r[4] for r in rows if r[4]) / len(rows), 'patterns': []}

        pattern_revenue = {}
        for row in rows:
            pattern = row[7] or 'unknown'
            if pattern not in pattern_revenue: pattern_revenue[pattern] = []
            if row[4]: pattern_revenue[pattern].append(row[4])

        for pattern, revenues in pattern_revenue.items():
            if revenues:
                analysis['patterns'].append({'pattern': pattern, 'count': len(revenues), 'avg_revenue': sum(revenues) / len(revenues), 'max_revenue': max(revenues), 'min_revenue': min(revenues)})

        return jsonify({'success': True, 'analysis': analysis})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/competitor/analyze', methods=['POST'])
@login_required
def analyze_competitor():
    """
    Analyze a competitor's YouTube channel or website to extract keyword opportunities.
    Returns ALL videos with their target keywords + aggregated keyword opportunities.
    """
    data = request.get_json()
    competitor = data.get('competitor', '').strip()
    comp_type = data.get('type', 'youtube')
    niche = data.get('niche', 'general')
    max_pages = data.get('max_pages', 3)  # How many pages of videos to fetch

    if not competitor:
        return jsonify({'success': False, 'error': 'Competitor name is required'}), 400

    results = {
        'success': True,
        'competitor': competitor,
        'type': comp_type,
        'niche': niche,
        'keywords': [],       # Aggregated unique keywords with metrics
        'all_videos': [],     # Full list of videos with target keywords
        'errors': []
    }

    try:
        if comp_type == 'youtube':
            # Get ALL videos from the competitor's YouTube channel
            yt_results = search_competitor_youtube(competitor)
            if yt_results.get('success'):
                videos = yt_results.get('videos', [])

                # Extract keywords - returns (aggregated_keywords, per_video_keywords)
                extracted_keywords, video_keywords = extract_keywords_from_videos(videos)

                # Store all videos with their target keywords
                results['all_videos'] = video_keywords
                results['video_count'] = len(videos)

                # Get volume data for aggregated keywords
                results['keywords'] = enrich_competitor_keywords(extracted_keywords, niche)

                # Also enrich the video keywords with volume data
                if video_keywords:
                    unique_targets = list(set(v['target_keyword'] for v in video_keywords if v['target_keyword']))
                    target_volumes = get_keyword_data_with_fallback(unique_targets[:50])  # API limit

                    volume_map = {}
                    if target_volumes.get('success') and target_volumes.get('data'):
                        for item in target_volumes['data']:
                            volume_map[item.get('keyword', '').lower()] = item.get('vol', 0)

                    # Add volume to each video's target keyword
                    for video in results['all_videos']:
                        kw = video.get('target_keyword', '').lower()
                        video['keyword_volume'] = volume_map.get(kw, 0)

            else:
                results['errors'].append(yt_results.get('error', 'YouTube search failed'))

        else:
            # Website analysis - search for site content
            web_results = search_competitor_website(competitor)
            if web_results.get('success'):
                results['keywords'] = enrich_competitor_keywords(web_results.get('keywords', []), niche)
            else:
                results['errors'].append(web_results.get('error', 'Website analysis failed'))

        # Sort aggregated keywords by priority score
        results['keywords'].sort(key=lambda x: x.get('priority_score', 0), reverse=True)

        # Sort videos by volume (highest first)
        results['all_videos'].sort(key=lambda x: x.get('keyword_volume', 0), reverse=True)

        return jsonify(results)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# CHANNEL KEYWORD ANALYSIS (NEW)
# ============================================

@app.route('/api/keyword/extract', methods=['POST'])
@login_required
def test_keyword_extraction():
    """Test endpoint to verify keyword extraction logic"""
    try:
        data = request.get_json()
        titles = data.get('titles', [])

        if isinstance(titles, str):
            titles = [titles]

        results = []
        for title in titles:
            extracted = extract_target_keyword(title)
            results.append({
                'input': title,
                'extracted': extracted
            })

        return jsonify({'success': True, 'results': results})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/channel/debug', methods=['POST'])
@login_required
def debug_channel_fetch():
    """Debug endpoint to see what's happening with channel video fetching"""
    try:
        data = request.get_json()
        channel = data.get('channel', '').strip()

        debug_info = {
            'input': channel,
            'youtube_api_key_configured': bool(YOUTUBE_API_KEY),
            'serpapi_key_configured': bool(SERPAPI_API_KEY),
            'steps': []
        }

        # Step 1: Find the channel
        debug_info['steps'].append({'step': 'Finding channel...'})
        channel_info = find_youtube_channel(channel)
        debug_info['channel_info'] = channel_info

        if channel_info.get('success'):
            channel_id = channel_info.get('channel_id')
            channel_name = channel_info.get('channel_name')
            debug_info['channel_id'] = channel_id
            debug_info['channel_name'] = channel_name

            # Step 2: Try YouTube Data API
            if YOUTUBE_API_KEY:
                debug_info['steps'].append({'step': 'Trying YouTube Data API...'})
                api_videos = fetch_videos_via_youtube_api(channel_id)
                debug_info['youtube_api_video_count'] = len(api_videos)
                debug_info['youtube_api_sample'] = [v.get('title', '')[:50] for v in api_videos[:5]]
            else:
                debug_info['steps'].append({'step': 'YouTube API key not configured, skipping'})

            # Step 3: Try SerpAPI strategies
            debug_info['steps'].append({'step': 'Trying SerpAPI strategies...'})
            all_videos = fetch_channel_videos_by_id(channel_id, channel_name=channel_name)
            debug_info['total_videos_found'] = len(all_videos)
            debug_info['video_sources'] = {}
            for v in all_videos:
                src = v.get('source', 'unknown')
                debug_info['video_sources'][src] = debug_info['video_sources'].get(src, 0) + 1

        return jsonify({'success': True, 'debug': debug_info})

    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()})

@app.route('/api/channel/analyze', methods=['POST'])
@login_required
def analyze_channel_keywords():
    """
    Analyze a YouTube channel's keyword publishing patterns.
    Scrapes all videos and analyzes:
    - How many times they publish on each keyword
    - Republishing frequency (time between videos on same keyword)
    - Most frequent keywords
    """
    try:
        data = request.get_json()
        channel = data.get('channel', '').strip()

        if not channel:
            return jsonify({'success': False, 'error': 'Channel is required'}), 400

        print(f"[CHANNEL ANALYSIS] Starting analysis for: {channel}")

        # Fetch all videos from the channel
        yt_results = search_competitor_youtube(channel)

        if not yt_results.get('success'):
            return jsonify({
                'success': False,
                'error': yt_results.get('error', 'Failed to fetch channel videos')
            }), 400

        videos = yt_results.get('videos', [])
        channel_name = yt_results.get('channel_name', channel)

        print(f"[CHANNEL ANALYSIS] Found {len(videos)} videos from {channel_name}")

        if not videos:
            return jsonify({
                'success': False,
                'error': 'No videos found for this channel'
            }), 404

        # Analyze keyword patterns from video titles
        keyword_analysis = analyze_keyword_patterns(videos, channel_name)

        return jsonify({
            'success': True,
            'channel': channel_name,
            'channel_id': yt_results.get('channel_id', ''),
            'total_videos': len(videos),
            'videos': videos,  # Return all videos
            'keyword_patterns': keyword_analysis['patterns'],
            'keyword_groups': keyword_analysis['groups'],
            'top_keywords': keyword_analysis['top_keywords'],
            'hot_keywords': keyword_analysis['hot_keywords'],  # Republished in last 12 months
            'publishing_stats': keyword_analysis['stats'],
            'republish_analysis': keyword_analysis['republish']
        })

    except Exception as e:
        print(f"[CHANNEL ANALYSIS] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

def detect_niche(text):
    """
    Detect the niche/category from a keyword or title.
    Returns the niche name or 'other' if not detected.
    """
    if not text:
        return 'other'

    text_lower = text.lower()

    # Niche definitions: {niche_name: [brand_names, category_terms]}
    NICHE_PATTERNS = {
        'vpn': {
            'brands': ['nordvpn', 'nord vpn', 'expressvpn', 'express vpn', 'surfshark', 'cyberghost',
                      'private internet access', 'pia', 'protonvpn', 'proton vpn', 'ipvanish',
                      'mullvad', 'windscribe', 'tunnelbear', 'hotspot shield', 'purevpn'],
            'terms': ['vpn', 'virtual private network']
        },
        'mattress': {
            'brands': ['purple', 'casper', 'nectar', 'saatva', 'helix', 'leesa', 'tuft and needle',
                      'tuft & needle', 'brooklyn bedding', 'dreamcloud', 'winkbed', 'avocado',
                      'tempur-pedic', 'tempurpedic', 'sleep number', 'beautyrest', 'serta'],
            'terms': ['mattress', 'bed', 'sleep', 'pillow', 'bedding', 'topper']
        },
        'parental_control': {
            'brands': ['bark', 'qustodio', 'net nanny', 'norton family', 'kaspersky safe kids',
                      'famisafe', 'ourpact', 'screen time', 'mobicip', 'circle', 'boomerang'],
            'terms': ['parental control', 'parental monitoring', 'kids safety', 'child safety',
                     'screen time', 'family safety']
        },
        'llc_formation': {
            'brands': ['zenbusiness', 'legalzoom', 'incfile', 'northwest registered agent',
                      'rocket lawyer', 'bizfilings', 'swyft filings', 'tailor brands',
                      'harbor compliance', 'mycorporation'],
            'terms': ['llc', 'incorporate', 'business formation', 'registered agent', 'ein']
        },
        'antivirus': {
            'brands': ['norton', 'mcafee', 'bitdefender', 'kaspersky', 'avast', 'avg', 'malwarebytes',
                      'eset', 'trend micro', 'webroot', 'totalav', 'intego', 'f-secure'],
            'terms': ['antivirus', 'anti-virus', 'malware', 'virus protection', 'internet security']
        },
        'identity_theft': {
            'brands': ['lifelock', 'aura', 'identity guard', 'identityforce', 'id watchdog',
                      'idshield', 'experian identityworks', 'credit sesame', 'privacy guard'],
            'terms': ['identity theft', 'identity protection', 'credit monitoring', 'dark web monitoring']
        },
        'password_manager': {
            'brands': ['lastpass', '1password', 'dashlane', 'bitwarden', 'keeper', 'roboform',
                      'nordpass', 'zoho vault', 'sticky password', 'enpass'],
            'terms': ['password manager', 'password vault', 'password keeper']
        },
        'web_hosting': {
            'brands': ['bluehost', 'siteground', 'hostinger', 'hostgator', 'dreamhost', 'a2 hosting',
                      'inmotion', 'greengeeks', 'wpengine', 'wp engine', 'cloudways', 'kinsta',
                      'godaddy', 'namecheap', 'ionos', 'scala hosting'],
            'terms': ['web hosting', 'hosting', 'wordpress hosting', 'vps', 'dedicated server',
                     'shared hosting', 'cloud hosting']
        },
        'email_marketing': {
            'brands': ['mailchimp', 'convertkit', 'constant contact', 'activecampaign', 'getresponse',
                      'aweber', 'drip', 'klaviyo', 'sendinblue', 'brevo', 'mailerlite', 'hubspot'],
            'terms': ['email marketing', 'newsletter', 'email automation', 'email list']
        },
        'home_security': {
            'brands': ['ring', 'simplisafe', 'adt', 'vivint', 'frontpoint', 'abode', 'cove',
                      'brinks', 'link interactive', 'scout', 'wyze', 'eufy', 'arlo', 'nest'],
            'terms': ['home security', 'security camera', 'security system', 'alarm system',
                     'doorbell camera', 'smart lock']
        },
        'pet': {
            'brands': ['fi', 'whistle', 'tractive', 'petcube', 'furbo', 'litter robot',
                      'chewy', 'petco', 'rover', 'wag', 'barkbox', 'ollie', 'nom nom', 'farmers dog'],
            'terms': ['pet', 'dog', 'cat', 'puppy', 'kitten', 'pet insurance', 'dog food', 'cat food',
                     'gps tracker', 'pet camera']
        },
        'website_builder': {
            'brands': ['wix', 'squarespace', 'weebly', 'shopify', 'wordpress', 'webflow',
                      'godaddy website builder', 'zyro', 'strikingly', 'carrd', 'duda'],
            'terms': ['website builder', 'site builder', 'web design', 'landing page', 'ecommerce']
        },
        'crm': {
            'brands': ['salesforce', 'hubspot', 'zoho crm', 'pipedrive', 'monday', 'freshsales',
                      'copper', 'insightly', 'agile crm', 'close'],
            'terms': ['crm', 'customer relationship', 'sales software', 'lead management']
        },
        'vpn_streaming': {
            'brands': [],  # Use VPN brands
            'terms': ['streaming', 'netflix', 'hulu', 'disney plus', 'amazon prime', 'bbc iplayer',
                     'unblock', 'geo-restriction']
        },
        'tax_software': {
            'brands': ['turbotax', 'h&r block', 'taxact', 'freetaxusa', 'taxslayer', 'jackson hewitt',
                      'credit karma tax', 'cash app taxes'],
            'terms': ['tax software', 'tax filing', 'tax return', 'tax prep']
        },
        'online_learning': {
            'brands': ['coursera', 'udemy', 'skillshare', 'masterclass', 'linkedin learning',
                      'pluralsight', 'datacamp', 'codecademy', 'brilliant', 'duolingo'],
            'terms': ['online course', 'online learning', 'e-learning', 'tutorial', 'certification']
        },
        'meal_delivery': {
            'brands': ['hellofresh', 'blue apron', 'home chef', 'green chef', 'factor', 'freshly',
                      'sunbasket', 'dinnerly', 'everyplate', 'gobble', 'marley spoon'],
            'terms': ['meal kit', 'meal delivery', 'food delivery', 'prepared meals']
        },
        'fitness': {
            'brands': ['peloton', 'mirror', 'tonal', 'bowflex', 'nordictrack', 'hydrow',
                      'beachbody', 'apple fitness', 'fitbit', 'whoop', 'oura'],
            'terms': ['fitness', 'workout', 'exercise', 'gym', 'treadmill', 'bike', 'rowing']
        },
        'data_removal': {
            'brands': ['deleteme', 'incogni', 'kanary', 'privacy duck', 'removaly', 'optery'],
            'terms': ['data broker', 'data removal', 'privacy', 'remove personal information',
                     'opt out', 'people search']
        }
    }

    # Check each niche
    for niche, patterns in NICHE_PATTERNS.items():
        # Check brands first (more specific)
        for brand in patterns.get('brands', []):
            if brand in text_lower:
                return niche

        # Check category terms
        for term in patterns.get('terms', []):
            if term in text_lower:
                return niche

    return 'other'

def extract_target_keyword(title):
    """
    Extract the target keyword from a YouTube video title.

    Rules:
    - Split on separators (|, -, :) and take first segment
    - Normalize "Top N" to "Best"
    - Remove years (2020-2029) from the end
    - Remove filler/clickbait words
    - Preserve original brand spelling (NordVPN vs Nord VPN)
    - Identify keyword type (review, comparison, best-of, etc.)

    Returns: {
        'keyword': 'nordvpn review',
        'keyword_normalized': 'nordvpn review',  # for grouping
        'keyword_type': 'review',
        'original_segment': 'NordVPN Review 2024'
    }
    """
    import re

    if not title:
        return None

    original_title = title

    # Step 1: Remove emojis and clean unicode
    title = re.sub(r'[^\x00-\x7F]+', ' ', title)  # Remove non-ASCII (emojis)
    title = title.strip()

    # Step 2: Split on major separators and take first segment
    # Priority: | then - then : then [ then (
    separators = [r'\s*\|\s*', r'\s+-\s+', r'\s*:\s*', r'\s*\[\s*', r'\s*\(\s*']

    segment = title
    for sep in separators:
        parts = re.split(sep, segment, maxsplit=1)
        if len(parts) > 1 and len(parts[0].strip()) >= 5:
            segment = parts[0].strip()
            break

    original_segment = segment

    # Step 3: Identify keyword type based on patterns
    keyword_type = 'other'
    segment_lower = segment.lower()

    # Comparison: "X vs Y" or "X versus Y"
    if re.search(r'\bvs\.?\b|\bversus\b', segment_lower):
        keyword_type = 'comparison'
    # Review patterns
    elif re.search(r'\breview\b', segment_lower):
        keyword_type = 'review'
    # Best-of patterns (including "Top N")
    elif re.search(r'\b(best|top\s*\d+)\b', segment_lower):
        keyword_type = 'best_of'
    # How-to patterns
    elif re.search(r'^how\s+to\b', segment_lower):
        keyword_type = 'how_to'
    # Deal/Coupon patterns
    elif re.search(r'\b(coupon|discount|deal|promo|code|offer|sale)\b', segment_lower):
        keyword_type = 'deal'
    # Tutorial/Guide
    elif re.search(r'\b(tutorial|guide|setup|install)\b', segment_lower):
        keyword_type = 'tutorial'

    # Step 4: Normalize "Top N" to "Best"
    segment = re.sub(r'\btop\s*\d+\b', 'Best', segment, flags=re.IGNORECASE)

    # Step 5: Remove years from the END only (preserve years in product names like "iPhone 15")
    # Match year at end, possibly with parentheses
    segment = re.sub(r'\s*\(?\s*20[2-3]\d\s*\)?\s*$', '', segment)

    # Step 6: Remove filler/clickbait words (usually at the end)
    filler_words = [
        r'\s*\b(honest|real|full|complete|ultimate|updated|unbiased|detailed)\b\s*$',
        r'\s*\b(must watch|watch this|you need|before you buy)\b.*$',
        r'\s*\b(my experience|my opinion|my thoughts)\b.*$',
        r'\s*[!?]+\s*$',  # Trailing punctuation
    ]
    for filler in filler_words:
        segment = re.sub(filler, '', segment, flags=re.IGNORECASE)

    # Step 7: Clean up extra whitespace
    segment = ' '.join(segment.split())
    segment = segment.strip()

    # Step 8: Create normalized version for grouping (lowercase, minimal)
    normalized = segment.lower()
    # Remove extra spaces and standardize
    normalized = ' '.join(normalized.split())

    # If segment is too short or empty, try to salvage from original
    if len(segment) < 3:
        segment = original_segment
        normalized = segment.lower()

    # Step 9: Detect niche from the keyword
    niche = detect_niche(segment)

    return {
        'keyword': segment,
        'keyword_normalized': normalized,
        'keyword_type': keyword_type,
        'niche': niche,
        'original_segment': original_segment,
        'original_title': original_title
    }

def analyze_keyword_patterns(videos, channel_name):
    """Analyze keyword publishing patterns from a list of videos using smart keyword extraction"""
    import re
    from datetime import datetime, timedelta
    from collections import defaultdict

    # Extract keywords from video titles
    keyword_counts = defaultdict(list)  # normalized_keyword -> list of video info
    keyword_first_published = {}
    keyword_last_published = {}

    # Helper to parse publish date
    def parse_date(date_str):
        if not date_str:
            return None
        try:
            original_date_str = date_str
            date_str_lower = date_str.lower().strip()

            # Handle ISO 8601 format from YouTube API (2024-01-15T10:30:00Z)
            if 'T' in original_date_str:
                try:
                    # Remove timezone suffix and parse
                    clean_date = original_date_str.replace('Z', '').split('.')[0]
                    return datetime.strptime(clean_date, '%Y-%m-%dT%H:%M:%S')
                except:
                    pass

            # Handle relative dates like "2 weeks ago", "3 months ago"
            if 'ago' in date_str_lower:
                now = datetime.now()

                if 'hour' in date_str_lower:
                    hours = int(re.search(r'(\d+)', date_str_lower).group(1))
                    return now - timedelta(hours=hours)
                elif 'day' in date_str_lower:
                    days = int(re.search(r'(\d+)', date_str_lower).group(1))
                    return now - timedelta(days=days)
                elif 'week' in date_str_lower:
                    weeks = int(re.search(r'(\d+)', date_str_lower).group(1))
                    return now - timedelta(weeks=weeks)
                elif 'month' in date_str_lower:
                    months = int(re.search(r'(\d+)', date_str_lower).group(1))
                    return now - timedelta(days=months * 30)
                elif 'year' in date_str_lower:
                    years = int(re.search(r'(\d+)', date_str_lower).group(1))
                    return now - timedelta(days=years * 365)

            # Try parsing various date formats
            for fmt in ['%b %d, %Y', '%Y-%m-%d', '%d %b %Y', '%B %d, %Y', '%Y-%m-%dT%H:%M:%S']:
                try:
                    return datetime.strptime(date_str_lower, fmt)
                except:
                    try:
                        return datetime.strptime(original_date_str, fmt)
                    except:
                        continue

            return None
        except:
            return None

    # Extract target keyword from each video using smart extraction
    for video in videos:
        title = video.get('title', '')
        published_date_str = video.get('published_date', '') or video.get('published_time', '')
        published_date = parse_date(published_date_str)
        views = video.get('views', 0)

        # Parse views
        if isinstance(views, str):
            views = views.lower().replace(' views', '').replace(',', '').replace('k', '000').replace('m', '000000')
            try:
                views = int(float(views))
            except:
                views = 0

        # Extract the target keyword using our smart extraction
        extracted = extract_target_keyword(title)

        if not extracted:
            continue

        keyword = extracted['keyword']
        keyword_normalized = extracted['keyword_normalized']
        keyword_type = extracted['keyword_type']
        niche = extracted['niche']

        # Track video info
        video_info = {
            'title': title,
            'link': video.get('link', ''),
            'published_date': published_date_str,
            'parsed_date': published_date.isoformat() if published_date else None,
            'views': views,
            'keyword_type': keyword_type,
            'niche': niche,
            'extracted_keyword': keyword
        }

        # Group by normalized keyword (for finding duplicates)
        keyword_counts[keyword_normalized].append(video_info)

        if published_date:
            if keyword_normalized not in keyword_first_published or published_date < parse_date(keyword_first_published[keyword_normalized]):
                keyword_first_published[keyword_normalized] = published_date_str
            if keyword_normalized not in keyword_last_published or published_date > parse_date(keyword_last_published[keyword_normalized]):
                keyword_last_published[keyword_normalized] = published_date_str

    # Calculate keyword statistics
    keyword_stats = []
    twelve_months_ago = datetime.now() - timedelta(days=365)

    for keyword_normalized, video_list in keyword_counts.items():
        if len(video_list) >= 1:  # Include all keywords (even single occurrence for debugging)
            total_views = sum(v.get('views', 0) for v in video_list)
            avg_views = total_views / len(video_list) if video_list else 0

            # Get the display keyword from the first video (preserves original casing)
            display_keyword = video_list[0].get('extracted_keyword', keyword_normalized)

            # Get the most common keyword type
            keyword_types = [v.get('keyword_type', 'other') for v in video_list]
            keyword_type = max(set(keyword_types), key=keyword_types.count)

            # Get the most common niche
            niches = [v.get('niche', 'other') for v in video_list]
            niche = max(set(niches), key=niches.count)

            # Calculate time between videos
            dates = [parse_date(v.get('published_date', '')) for v in video_list]
            dates = [d for d in dates if d]
            dates.sort()

            republish_interval_days = None
            if len(dates) >= 2:
                intervals = [(dates[i+1] - dates[i]).days for i in range(len(dates)-1)]
                republish_interval_days = sum(intervals) / len(intervals)

            # Calculate recent (last 12 months) stats
            recent_videos = [v for v in video_list if parse_date(v.get('published_date', '')) and parse_date(v.get('published_date', '')) >= twelve_months_ago]
            recent_count = len(recent_videos)
            recent_views = sum(v.get('views', 0) for v in recent_videos)

            # Calculate view distribution pattern for this keyword's videos
            view_counts = sorted([v.get('views', 0) for v in video_list], reverse=True)
            view_pattern = 'no_data'
            if len(view_counts) >= 3 and sum(view_counts) > 0:
                total = sum(view_counts)
                top_share = view_counts[0] / total
                top3_share = sum(view_counts[:3]) / total
                if top_share > 0.5:
                    view_pattern = 'winner_take_all'
                elif top3_share > 0.7:
                    view_pattern = 'top_heavy'
                else:
                    view_pattern = 'distributed'

            # Conversion immediacy based on keyword type
            conversion_immediacy_map = {
                'deal': 'high',      # People ready to buy with coupon/deal
                'comparison': 'high', # Comparing options = close to decision
                'review': 'medium',   # Researching specific product
                'best_of': 'medium',  # Looking for recommendations
                'informational': 'low',  # Just learning
                'other': 'medium'
            }
            conversion_immediacy = conversion_immediacy_map.get(keyword_type, 'medium')

            # Estimate revenue potential using avg_views as proxy for traffic
            # EPV by keyword type from calibrated model
            epv_by_type = {
                'deal': 1.18, 'comparison': 0.53, 'review': 0.31,
                'best_of': 0.16, 'informational': 0.10, 'other': 0.17
            }
            base_epv = epv_by_type.get(keyword_type, 0.17)

            # Niche multiplier
            niche_multipliers = {
                'vpn': 1.5, 'identity_theft': 1.4, 'data_broker_removal': 1.3,
                'antivirus': 1.2, 'web_hosting': 1.3, 'email_marketing': 1.2,
                'parental_control': 1.1, 'home_security': 1.0, 'pet_tech': 1.0,
                'mattress': 1.1, 'llc_formation': 1.2
            }
            niche_mult = niche_multipliers.get(niche, 1.0)

            # Traffic capture rate based on view distribution
            capture_rates = {
                'distributed': 0.15, 'top_heavy': 0.08,
                'winner_take_all': 0.03, 'no_data': 0.10
            }
            capture_rate = capture_rates.get(view_pattern, 0.10)

            # Calculate willingness to spend (% of searchers willing to pay)
            willingness = estimate_willingness_to_spend(display_keyword, keyword_type, niche)

            # Estimate monthly traffic from avg_views (rough proxy)
            # Assume avg_views represents ~30% of monthly search traffic for top results
            estimated_monthly_traffic = avg_views * 3 * capture_rate
            adjusted_epv = base_epv * niche_mult

            # Revenue potential = traffic × EPV × willingness to spend
            revenue_potential = round(estimated_monthly_traffic * adjusted_epv * willingness, 2)

            keyword_stats.append({
                'keyword': display_keyword,
                'keyword_normalized': keyword_normalized,
                'keyword_type': keyword_type,
                'niche': niche,
                'count': len(video_list),
                'total_views': total_views,
                'avg_views': int(avg_views),
                'first_published': keyword_first_published.get(keyword_normalized, ''),
                'last_published': keyword_last_published.get(keyword_normalized, ''),
                'republish_interval_days': round(republish_interval_days, 1) if republish_interval_days else None,
                'recent_count': recent_count,  # Videos in last 12 months
                'recent_views': recent_views,
                'is_hot': recent_count >= 2,  # Republished recently
                'view_pattern': view_pattern,  # View distribution pattern
                'conversion_immediacy': conversion_immediacy,  # How close to purchase
                'willingness_to_spend': willingness,  # % of searchers willing to pay
                'revenue_potential': revenue_potential,  # Estimated $/month (adjusted by willingness)
                'epv': round(adjusted_epv, 2),  # Earnings per visitor
                'capture_rate': round(capture_rate * 100, 1),  # Traffic capture %
                'videos': video_list[:5]  # Include first 5 videos as examples
            })

    # Sort by count (most frequent first)
    keyword_stats.sort(key=lambda x: x['count'], reverse=True)

    # Filter to only keywords with 2+ videos for most stats
    repeated_keywords = [k for k in keyword_stats if k['count'] >= 2]

    # Hot keywords - republished 2+ times in last 12 months
    hot_keywords = sorted(
        [k for k in keyword_stats if k['recent_count'] >= 2],
        key=lambda x: x['recent_count'],
        reverse=True
    )

    # Group keywords by niche
    niche_groups = {}
    for k in repeated_keywords:
        niche = k['niche']
        if niche not in niche_groups:
            niche_groups[niche] = []
        niche_groups[niche].append(k)

    # Sort each niche group by count
    for niche in niche_groups:
        niche_groups[niche].sort(key=lambda x: x['count'], reverse=True)
        niche_groups[niche] = niche_groups[niche][:20]  # Top 20 per niche

    # Group keywords by category
    keyword_groups = {
        'frequent_topics': [k for k in repeated_keywords if k['count'] >= 5][:20],
        'repeated_keywords': [k for k in repeated_keywords if 2 <= k['count'] < 5][:30],
        'high_view_keywords': sorted(repeated_keywords, key=lambda x: x['avg_views'], reverse=True)[:20],
        # Hot keywords - actively republishing in last 12 months
        'hot_recent': hot_keywords[:20],
        # Group by keyword type
        'reviews': [k for k in repeated_keywords if k['keyword_type'] == 'review'][:15],
        'comparisons': [k for k in repeated_keywords if k['keyword_type'] == 'comparison'][:15],
        'best_of': [k for k in repeated_keywords if k['keyword_type'] == 'best_of'][:15],
        'deals': [k for k in repeated_keywords if k['keyword_type'] == 'deal'][:15],
        # Group by niche
        'by_niche': niche_groups,
    }

    # Calculate overall publishing stats
    all_dates = []
    for video in videos:
        d = parse_date(video.get('published_date', '') or video.get('published_time', ''))
        if d:
            all_dates.append(d)

    all_dates.sort()

    # Find the most repeated keyword (count >= 2)
    most_used = repeated_keywords[0] if repeated_keywords else None
    hottest = hot_keywords[0] if hot_keywords else None

    # Count niches
    niche_counts = {}
    for k in repeated_keywords:
        niche = k['niche']
        niche_counts[niche] = niche_counts.get(niche, 0) + 1

    publishing_stats = {
        'total_videos': len(videos),
        'unique_keywords_found': len(repeated_keywords),
        'total_unique_keywords': len(keyword_stats),
        'most_used_keyword': most_used['keyword'] if most_used else None,
        'most_used_keyword_count': most_used['count'] if most_used else 0,
        'hot_keywords_count': len(hot_keywords),  # Keywords republished in last 12 months
        'hottest_keyword': hottest['keyword'] if hottest else None,
        'hottest_keyword_recent_count': hottest['recent_count'] if hottest else 0,
        'niches_found': list(niche_counts.keys()),
        'niche_counts': niche_counts,
    }

    if len(all_dates) >= 2:
        days_range = (all_dates[-1] - all_dates[0]).days
        publishing_stats['date_range_days'] = days_range
        publishing_stats['avg_videos_per_month_alltime'] = round(len(videos) / max(1, days_range / 30), 1)
        publishing_stats['first_video_date'] = all_dates[0].strftime('%Y-%m-%d')
        publishing_stats['last_video_date'] = all_dates[-1].strftime('%Y-%m-%d')

        # Calculate RECENT publishing rate (last 90 days) - more accurate for active channels
        ninety_days_ago = datetime.now() - timedelta(days=90)
        recent_videos = [d for d in all_dates if d >= ninety_days_ago]
        if len(recent_videos) >= 3:  # Need at least a few videos to calculate rate
            publishing_stats['avg_videos_per_month'] = round(len(recent_videos) / 3, 1)  # 90 days = 3 months
            publishing_stats['videos_last_90_days'] = len(recent_videos)
        else:
            # Fall back to all-time if not enough recent data
            publishing_stats['avg_videos_per_month'] = publishing_stats['avg_videos_per_month_alltime']
            publishing_stats['videos_last_90_days'] = len(recent_videos)

    # Republish analysis - which keywords get republished most often
    republish_analysis = sorted(
        [k for k in keyword_stats if k['republish_interval_days'] is not None],
        key=lambda x: x['republish_interval_days']
    )[:20]

    return {
        'patterns': repeated_keywords[:50],  # Top 50 repeated keywords
        'all_keywords': keyword_stats[:100],  # All keywords including single-use
        'hot_keywords': hot_keywords[:30],  # Keywords republished in last 12 months
        'groups': keyword_groups,
        'top_keywords': [{'keyword': k['keyword'], 'keyword_type': k['keyword_type'], 'niche': k['niche'], 'count': k['count'], 'avg_views': k['avg_views'], 'recent_count': k['recent_count']} for k in repeated_keywords[:20]],
        'stats': publishing_stats,
        'republish': republish_analysis
    }

def search_competitor_youtube(competitor):
    """
    Get ALL videos from a YouTube channel using SerpAPI.
    Accepts: channel URL, channel handle (@name), or channel name.
    """
    try:
        if not SERPAPI_API_KEY:
            return {'success': False, 'error': 'SerpAPI key not configured'}

        import re

        # Extract channel identifier from various URL formats
        channel_id = None
        channel_handle = None
        method_used = None

        print(f"Analyzing competitor: {competitor}")

        # Check if it's a URL
        if 'youtube.com' in competitor or 'youtu.be' in competitor:
            # Handle various YouTube URL formats
            # /channel/UC... format
            channel_match = re.search(r'/channel/(UC[a-zA-Z0-9_-]+)', competitor)
            if channel_match:
                channel_id = channel_match.group(1)
                method_used = 'direct_channel_id'
                print(f"Found channel ID from URL: {channel_id}")

            # /@handle format
            handle_match = re.search(r'/@([a-zA-Z0-9_-]+)', competitor)
            if handle_match:
                channel_handle = handle_match.group(1)
                method_used = 'handle_from_url'
                print(f"Found handle from URL: @{channel_handle}")

            # /c/CustomName or /user/Username format
            custom_match = re.search(r'/(?:c|user)/([a-zA-Z0-9_-]+)', competitor)
            if custom_match:
                channel_handle = custom_match.group(1)
                method_used = 'custom_url'
                print(f"Found custom/user name from URL: {channel_handle}")

        # Check if it's a handle (starts with @)
        elif competitor.startswith('@'):
            channel_handle = competitor[1:]
            method_used = 'handle_direct'
            print(f"Direct handle input: @{channel_handle}")

        # Otherwise treat as channel name to search for
        else:
            channel_handle = competitor
            method_used = 'name_search'
            print(f"Will search for channel name: {channel_handle}")

        all_videos = []
        channel_name = None

        # If we have a channel ID, use it directly
        if channel_id:
            print(f"Fetching videos using channel ID: {channel_id}")
            # Try to get channel name first if we don't have it
            if not channel_name:
                channel_info = find_youtube_channel(channel_id)
                channel_name = channel_info.get('channel_name', competitor)
            videos = fetch_channel_videos_by_id(channel_id, channel_name=channel_name)
            all_videos.extend(videos)
        else:
            # First, search for the channel to get its ID
            print(f"Searching for channel: {channel_handle or competitor}")
            channel_info = find_youtube_channel(channel_handle or competitor)
            if channel_info.get('success') and channel_info.get('channel_id'):
                channel_id = channel_info['channel_id']
                channel_name = channel_info.get('channel_name', '')
                print(f"Found channel: {channel_name} (ID: {channel_id})")
                videos = fetch_channel_videos_by_id(channel_id, channel_name=channel_name)
                all_videos.extend(videos)
            else:
                # Fallback: search YouTube for videos mentioning the competitor
                print(f"Channel not found, using fallback search for: {competitor}")
                method_used = 'fallback_search'
                fallback_videos = search_youtube_videos(competitor)
                all_videos.extend(fallback_videos)

        print(f"Total videos found: {len(all_videos)}")

        return {
            'success': True,
            'videos': all_videos,
            'total_found': len(all_videos),
            'channel_id': channel_id,
            'channel_name': channel_name,
            'method_used': method_used
        }

    except Exception as e:
        print(f"Error in search_competitor_youtube: {e}")
        return {'success': False, 'error': str(e)}

def find_youtube_channel(query):
    """Search for a YouTube channel and return its ID using multiple strategies"""
    import re

    print(f"[FIND_CHANNEL] Searching for: {query}")

    # Strategy 1: If we have a YouTube API key, use it to resolve handles directly
    if YOUTUBE_API_KEY:
        print("[FIND_CHANNEL] Trying YouTube Data API...")
        result = find_channel_via_youtube_api(query)
        if result.get('success'):
            print(f"[FIND_CHANNEL] Found via YouTube API: {result.get('channel_name')} ({result.get('channel_id')})")
            return result

    # Strategy 2: Try SerpAPI with channel filter
    print("[FIND_CHANNEL] Trying SerpAPI with channel filter...")
    try:
        url = "https://serpapi.com/search.json"
        params = {
            "engine": "youtube",
            "search_query": query,
            "api_key": SERPAPI_API_KEY,
            "sp": "EgIQAg=="  # Filter for channels only
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            channels = data.get('channel_results', [])

            if channels:
                channel = channels[0]
                channel_link = channel.get('link', '')
                match = re.search(r'/channel/(UC[a-zA-Z0-9_-]+)', channel_link)
                if match:
                    print(f"[FIND_CHANNEL] Found via SerpAPI channel search: {channel.get('title')}")
                    return {
                        'success': True,
                        'channel_id': match.group(1),
                        'channel_name': channel.get('title', ''),
                        'subscribers': channel.get('subscribers', '')
                    }
    except Exception as e:
        print(f"[FIND_CHANNEL] SerpAPI channel search error: {e}")

    # Strategy 3: Try SerpAPI without channel filter (search videos, extract channel)
    print("[FIND_CHANNEL] Trying SerpAPI video search...")
    try:
        # Try different query variations
        search_queries = [query]
        if query.startswith('@'):
            # Convert handle to readable name
            clean_name = query[1:].replace('_', ' ').replace('-', ' ')
            search_queries.append(clean_name)
            search_queries.append(f'"{clean_name}"')

        for search_query in search_queries:
            params = {
                "engine": "youtube",
                "search_query": search_query,
                "api_key": SERPAPI_API_KEY
            }

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()

                # Check channel results first
                channels = data.get('channel_results', [])
                if channels:
                    channel = channels[0]
                    channel_link = channel.get('link', '')
                    match = re.search(r'/channel/(UC[a-zA-Z0-9_-]+)', channel_link)
                    if match:
                        print(f"[FIND_CHANNEL] Found channel in results: {channel.get('title')}")
                        return {
                            'success': True,
                            'channel_id': match.group(1),
                            'channel_name': channel.get('title', ''),
                            'subscribers': channel.get('subscribers', '')
                        }

                # Check video results for channel info
                videos = data.get('video_results', [])
                for video in videos:
                    channel_info = video.get('channel', {})
                    if isinstance(channel_info, dict):
                        channel_link = channel_info.get('link', '')
                        channel_name = channel_info.get('name', '')
                    else:
                        continue

                    match = re.search(r'/channel/(UC[a-zA-Z0-9_-]+)', channel_link)
                    if match:
                        # Check if this channel matches our query
                        query_lower = query.lower().replace('@', '').replace('_', '').replace('-', '')
                        name_lower = channel_name.lower().replace(' ', '').replace('_', '').replace('-', '')

                        if query_lower in name_lower or name_lower in query_lower:
                            print(f"[FIND_CHANNEL] Found matching channel from video: {channel_name}")
                            return {
                                'success': True,
                                'channel_id': match.group(1),
                                'channel_name': channel_name
                            }

    except Exception as e:
        print(f"[FIND_CHANNEL] SerpAPI video search error: {e}")

    print("[FIND_CHANNEL] Channel not found with any strategy")
    return {'success': False, 'error': 'Channel not found'}

def find_channel_via_youtube_api(query):
    """Use YouTube Data API to find a channel by handle or name"""
    try:
        if not YOUTUBE_API_KEY:
            return {'success': False, 'error': 'No YouTube API key'}

        import re

        # Clean up the query
        search_term = query.strip()
        if search_term.startswith('@'):
            search_term = search_term[1:]

        # Method 1: Try to search for the channel directly
        url = "https://www.googleapis.com/youtube/v3/search"
        params = {
            'part': 'snippet',
            'q': search_term,
            'type': 'channel',
            'maxResults': 5,
            'key': YOUTUBE_API_KEY
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            items = data.get('items', [])

            for item in items:
                channel_id = item.get('id', {}).get('channelId')
                snippet = item.get('snippet', {})
                channel_title = snippet.get('title', '')

                if channel_id:
                    # Check if this matches our query
                    query_lower = search_term.lower().replace('_', '').replace('-', '').replace(' ', '')
                    title_lower = channel_title.lower().replace('_', '').replace('-', '').replace(' ', '')

                    if query_lower in title_lower or title_lower in query_lower or len(items) == 1:
                        return {
                            'success': True,
                            'channel_id': channel_id,
                            'channel_name': channel_title,
                            'description': snippet.get('description', '')[:100]
                        }

        # Method 2: Try forHandle parameter (for @handles)
        if query.startswith('@'):
            url = "https://www.googleapis.com/youtube/v3/channels"
            params = {
                'part': 'snippet,contentDetails',
                'forHandle': query,  # Include the @ symbol
                'key': YOUTUBE_API_KEY
            }

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])

                if items:
                    item = items[0]
                    return {
                        'success': True,
                        'channel_id': item.get('id'),
                        'channel_name': item.get('snippet', {}).get('title', ''),
                        'description': item.get('snippet', {}).get('description', '')[:100]
                    }

        return {'success': False, 'error': 'Channel not found via YouTube API'}

    except Exception as e:
        print(f"[YT_API_FIND] Error: {e}")
        return {'success': False, 'error': str(e)}

def fetch_videos_via_youtube_api(channel_id, max_results=10000):
    """
    Fetch ALL videos from a YouTube channel using the official YouTube Data API.
    This is the ONLY reliable way to get all videos from a channel.

    Default limit is 10,000 videos which should cover virtually any channel.
    Each API call fetches 50 videos and costs ~1 quota unit.

    Requires YOUTUBE_API_KEY environment variable to be set.
    Get a free API key from: https://console.cloud.google.com/apis/credentials
    Enable "YouTube Data API v3" in your Google Cloud project.
    """
    all_videos = []

    try:
        if not YOUTUBE_API_KEY:
            print("[YT_API] No YouTube API key configured")
            return all_videos

        import time

        # Step 1: Get the channel's uploads playlist ID
        # The uploads playlist ID is "UU" + channel_id[2:] (replace UC with UU)
        if channel_id.startswith('UC'):
            uploads_playlist_id = 'UU' + channel_id[2:]
        else:
            # Need to fetch channel info first to get the uploads playlist
            print(f"[YT_API] Fetching channel info for: {channel_id}")
            channel_url = f"https://www.googleapis.com/youtube/v3/channels"
            params = {
                'part': 'contentDetails',
                'id': channel_id,
                'key': YOUTUBE_API_KEY
            }
            response = requests.get(channel_url, params=params, timeout=30)
            if response.status_code != 200:
                print(f"[YT_API] Channel fetch error: {response.status_code}")
                return all_videos

            data = response.json()
            items = data.get('items', [])
            if not items:
                print("[YT_API] Channel not found")
                return all_videos

            uploads_playlist_id = items[0].get('contentDetails', {}).get('relatedPlaylists', {}).get('uploads')
            if not uploads_playlist_id:
                print("[YT_API] No uploads playlist found")
                return all_videos

        print(f"[YT_API] Fetching videos from playlist: {uploads_playlist_id}")

        # Step 2: Fetch all videos from the uploads playlist
        playlist_url = "https://www.googleapis.com/youtube/v3/playlistItems"
        page_token = None
        total_fetched = 0

        while total_fetched < max_results:
            params = {
                'part': 'snippet',
                'playlistId': uploads_playlist_id,
                'maxResults': 50,  # Max allowed per request
                'key': YOUTUBE_API_KEY
            }
            if page_token:
                params['pageToken'] = page_token

            response = requests.get(playlist_url, params=params, timeout=30)

            if response.status_code != 200:
                print(f"[YT_API] Playlist fetch error: {response.status_code}")
                error_data = response.json()
                print(f"[YT_API] Error details: {error_data.get('error', {}).get('message', 'Unknown')}")
                break

            data = response.json()
            items = data.get('items', [])

            if not items:
                print("[YT_API] No more videos in playlist")
                break

            for item in items:
                snippet = item.get('snippet', {})
                video_id = snippet.get('resourceId', {}).get('videoId')

                if video_id:
                    video = {
                        'video_id': video_id,
                        'title': snippet.get('title', ''),
                        'link': f'https://www.youtube.com/watch?v={video_id}',
                        'published_date': snippet.get('publishedAt', ''),
                        'description': snippet.get('description', '')[:200],
                        'thumbnail': snippet.get('thumbnails', {}).get('medium', {}).get('url', ''),
                        'channel': {
                            'name': snippet.get('channelTitle', ''),
                            'id': snippet.get('channelId', '')
                        }
                    }
                    all_videos.append(video)
                    total_fetched += 1

            print(f"[YT_API] Fetched {len(items)} videos (total: {total_fetched})")

            # Check for next page
            page_token = data.get('nextPageToken')
            if not page_token:
                print("[YT_API] No more pages")
                break

            time.sleep(0.1)  # Small delay to avoid rate limiting

        print(f"[YT_API] Total videos fetched: {len(all_videos)}")

        # Step 3: Fetch view counts for all videos (in batches of 50)
        if all_videos:
            print(f"[YT_API] Fetching view counts for {len(all_videos)} videos...")
            video_ids = [v.get('video_id') for v in all_videos if v.get('video_id')]
            view_counts = {}

            # Process in batches of 50
            for i in range(0, len(video_ids), 50):
                batch_ids = video_ids[i:i+50]
                videos_url = "https://www.googleapis.com/youtube/v3/videos"
                params = {
                    'part': 'statistics',
                    'id': ','.join(batch_ids),
                    'key': YOUTUBE_API_KEY
                }

                try:
                    response = requests.get(videos_url, params=params, timeout=30)
                    if response.status_code == 200:
                        data = response.json()
                        for item in data.get('items', []):
                            vid_id = item.get('id')
                            stats = item.get('statistics', {})
                            view_counts[vid_id] = int(stats.get('viewCount', 0))
                    else:
                        print(f"[YT_API] View count fetch error: {response.status_code}")
                except Exception as e:
                    print(f"[YT_API] View count batch error: {e}")

                time.sleep(0.05)  # Small delay between batches

            # Update videos with view counts
            for video in all_videos:
                vid_id = video.get('video_id')
                if vid_id and vid_id in view_counts:
                    video['views'] = view_counts[vid_id]
                else:
                    video['views'] = 0

            total_views = sum(view_counts.values())
            print(f"[YT_API] Fetched view counts. Total views: {total_views:,}")

        return all_videos

    except Exception as e:
        print(f"[YT_API] Error: {e}")
        import traceback
        traceback.print_exc()
        return all_videos

def fetch_channel_videos_by_id(channel_id, max_pages=100, channel_name=None):
    """Fetch ALL videos from a YouTube channel using multiple strategies"""
    all_videos = []
    seen_video_ids = set()  # Track seen videos to avoid duplicates

    try:
        import time
        import re

        print(f"[FETCH] Starting comprehensive video fetch for: {channel_name or channel_id}")

        # Strategy 0: Use YouTube Data API (most reliable, if key is configured)
        if YOUTUBE_API_KEY and channel_id:
            print(f"[FETCH] Strategy 0: YouTube Data API (most reliable)...")
            api_videos = fetch_videos_via_youtube_api(channel_id)
            for video in api_videos:
                video_id = video.get('video_id') or extract_video_id(video)
                if video_id and video_id not in seen_video_ids:
                    seen_video_ids.add(video_id)
                    video['source'] = 'youtube_data_api'
                    all_videos.append(video)
            print(f"[FETCH] Strategy 0 found {len(all_videos)} videos via YouTube Data API")

            # If we got a good number of videos from the API, we're done
            if len(all_videos) >= 50:
                print(f"[FETCH] Got sufficient videos from YouTube API, skipping other strategies")
                return all_videos

        # Strategy 1: Use Google search with site:youtube.com to find channel videos
        # This is more effective than YouTube search for getting all videos
        if channel_name:
            print(f"[FETCH] Strategy 1: Google site search for channel videos...")
            google_videos = fetch_videos_via_google_search(channel_name, max_pages=20)
            for video in google_videos:
                video_id = extract_video_id(video)
                if video_id and video_id not in seen_video_ids:
                    seen_video_ids.add(video_id)
                    video['source'] = 'google_site_search'
                    all_videos.append(video)
            print(f"[FETCH] Strategy 1 found {len(all_videos)} videos")

        # Strategy 2: YouTube search with channel name (various queries)
        if channel_name:
            print(f"[FETCH] Strategy 2: YouTube search variations...")
            search_queries = [
                f'"{channel_name}"',  # Exact match
                channel_name,  # Loose match
                f'{channel_name} review',  # Common video types
                f'{channel_name} best',
                f'{channel_name} 2024',
                f'{channel_name} 2023',
            ]

            for query in search_queries:
                yt_videos = search_youtube_with_query(query, max_pages=10, channel_filter=channel_name)
                for video in yt_videos:
                    video_id = extract_video_id(video)
                    if video_id and video_id not in seen_video_ids:
                        seen_video_ids.add(video_id)
                        video['source'] = 'youtube_search'
                        all_videos.append(video)
                time.sleep(0.2)

            print(f"[FETCH] Strategy 2 total: {len(all_videos)} videos")

        # Strategy 3: Search with sort by date (oldest and newest)
        if channel_name and len(all_videos) < 100:
            print(f"[FETCH] Strategy 3: Date-sorted searches...")
            for sort_mode in ['CAI%3D', 'CAISAhAB']:  # newest, oldest
                sorted_videos = search_youtube_sorted(channel_name, sp_param=sort_mode, max_pages=10)
                for video in sorted_videos:
                    video_id = extract_video_id(video)
                    if video_id and video_id not in seen_video_ids:
                        # Verify it's from the right channel
                        video_channel = video.get('channel', {})
                        if isinstance(video_channel, dict):
                            video_channel_name = video_channel.get('name', '')
                        else:
                            video_channel_name = str(video_channel)

                        if channel_name.lower() in video_channel_name.lower() or video_channel_name.lower() in channel_name.lower():
                            seen_video_ids.add(video_id)
                            video['source'] = 'youtube_sorted'
                            all_videos.append(video)
                time.sleep(0.2)

            print(f"[FETCH] Strategy 3 total: {len(all_videos)} videos")

        print(f"[FETCH] Total videos fetched: {len(all_videos)}")
        return all_videos

    except Exception as e:
        print(f"Error fetching channel videos: {e}")
        import traceback
        traceback.print_exc()
        return all_videos

def extract_video_id(video):
    """Extract video ID from various video object formats"""
    import re
    video_link = video.get('link', '') or video.get('url', '')
    video_id = video.get('video_id') or video.get('id')

    if not video_id and video_link:
        # Extract from YouTube URL
        match = re.search(r'(?:v=|youtu\.be/)([a-zA-Z0-9_-]{11})', video_link)
        if match:
            video_id = match.group(1)

    return video_id

def fetch_videos_via_google_search(channel_name, max_pages=20):
    """Use Google search to find all videos from a YouTube channel"""
    all_videos = []
    seen_urls = set()

    try:
        import time
        url = "https://serpapi.com/search.json"

        # Search Google for YouTube videos from this channel
        search_query = f'site:youtube.com/watch "{channel_name}"'

        params = {
            "engine": "google",
            "q": search_query,
            "api_key": SERPAPI_API_KEY,
            "num": 100  # Get max results per page
        }

        page_count = 0
        start = 0

        while page_count < max_pages:
            page_count += 1
            params['start'] = start

            print(f"[GOOGLE] Page {page_count}, start={start}...")

            response = requests.get(url, params=params, timeout=60)

            if response.status_code != 200:
                print(f"[GOOGLE] API error: {response.status_code}")
                break

            data = response.json()
            organic = data.get('organic_results', [])

            if not organic:
                print("[GOOGLE] No more results")
                break

            new_count = 0
            for result in organic:
                link = result.get('link', '')
                if 'youtube.com/watch' in link and link not in seen_urls:
                    seen_urls.add(link)
                    # Convert to video format
                    video = {
                        'title': result.get('title', ''),
                        'link': link,
                        'snippet': result.get('snippet', ''),
                        'published_date': result.get('date', ''),
                    }
                    all_videos.append(video)
                    new_count += 1

            print(f"[GOOGLE] Added {new_count} videos (total: {len(all_videos)})")

            if new_count == 0:
                break

            # Check for next page
            pagination = data.get('serpapi_pagination', {})
            if not pagination.get('next'):
                break

            start += 100
            time.sleep(0.3)

        return all_videos

    except Exception as e:
        print(f"[GOOGLE] Error: {e}")
        return all_videos

def search_youtube_with_query(query, max_pages=5, channel_filter=None):
    """Search YouTube with a specific query and optionally filter by channel"""
    all_videos = []

    try:
        import time
        url = "https://serpapi.com/search.json"

        params = {
            "engine": "youtube",
            "search_query": query,
            "api_key": SERPAPI_API_KEY
        }

        page_count = 0
        while page_count < max_pages:
            page_count += 1

            response = requests.get(url, params=params, timeout=60)

            if response.status_code != 200:
                break

            data = response.json()
            videos = data.get('video_results', [])

            if not videos:
                break

            for video in videos:
                # If channel filter is set, verify the video is from that channel
                if channel_filter:
                    video_channel = video.get('channel', {})
                    if isinstance(video_channel, dict):
                        video_channel_name = video_channel.get('name', '')
                    else:
                        video_channel_name = str(video_channel)

                    # Flexible matching
                    if not (channel_filter.lower() in video_channel_name.lower() or
                            video_channel_name.lower() in channel_filter.lower()):
                        continue

                all_videos.append(video)

            # Get next page
            serpapi_pagination = data.get('serpapi_pagination', {})
            next_page_token = serpapi_pagination.get('next_page_token')

            if not next_page_token:
                break

            params['sp'] = next_page_token
            time.sleep(0.2)

        return all_videos

    except Exception as e:
        print(f"[YT_SEARCH] Error: {e}")
        return all_videos

def search_youtube_sorted(channel_name, sp_param, max_pages=10):
    """Search YouTube with specific sort parameter"""
    all_videos = []

    try:
        import time
        url = "https://serpapi.com/search.json"

        params = {
            "engine": "youtube",
            "search_query": f'"{channel_name}"',
            "api_key": SERPAPI_API_KEY,
            "sp": sp_param
        }

        page_count = 0
        while page_count < max_pages:
            page_count += 1

            response = requests.get(url, params=params, timeout=60)

            if response.status_code != 200:
                break

            data = response.json()
            videos = data.get('video_results', [])

            if not videos:
                break

            all_videos.extend(videos)

            # Get next page
            serpapi_pagination = data.get('serpapi_pagination', {})
            next_page_token = serpapi_pagination.get('next_page_token')

            if not next_page_token:
                break

            params['sp'] = next_page_token
            time.sleep(0.2)

        return all_videos

    except Exception as e:
        print(f"[YT_SORTED] Error: {e}")
        return all_videos

def fetch_channel_videos_via_search(channel_id, max_pages=20, channel_name=None):
    """Fetch channel videos using YouTube search as fallback"""
    all_videos = []
    seen_video_ids = set()

    try:
        import time
        url = "https://serpapi.com/search.json"

        # Try multiple search strategies
        search_queries = []

        # Strategy 1: Direct channel filter
        search_queries.append(f"site:youtube.com/watch channel:{channel_id}")

        # Strategy 2: If we have channel name, search by name
        if channel_name:
            search_queries.append(f'"{channel_name}" site:youtube.com')

        for search_query in search_queries:
            params = {
                "engine": "youtube",
                "search_query": search_query,
                "api_key": SERPAPI_API_KEY
            }

            page_count = 0
            while page_count < max_pages:
                page_count += 1
                print(f"Search fallback page {page_count} with query: {search_query[:50]}...")

                response = requests.get(url, params=params, timeout=60)

                if response.status_code != 200:
                    print(f"Search API error: {response.status_code}")
                    break

                data = response.json()
                videos = data.get('video_results', [])

                if not videos:
                    print("No more videos in search results")
                    break

                new_count = 0
                for video in videos:
                    video_id = video.get('link', '')
                    if video_id and video_id not in seen_video_ids:
                        seen_video_ids.add(video_id)
                        video['source'] = 'channel_search'
                        all_videos.append(video)
                        new_count += 1

                print(f"Added {new_count} new videos from search (total: {len(all_videos)})")

                if new_count == 0:
                    break

                # Get next page token
                serpapi_pagination = data.get('serpapi_pagination', {})
                next_page_token = serpapi_pagination.get('next_page_token')

                if not next_page_token:
                    break

                params['sp'] = next_page_token
                time.sleep(0.3)

            # If we got enough videos, stop trying other queries
            if len(all_videos) >= 50:
                break

        print(f"Search fallback total: {len(all_videos)} videos")
        return all_videos

    except Exception as e:
        print(f"Error in search fallback: {e}")
        return all_videos

def search_youtube_videos(query, max_results=50):
    """Fallback: search YouTube for videos (when channel ID not found)"""
    all_videos = []

    try:
        url = "https://serpapi.com/search.json"
        params = {
            "engine": "youtube",
            "search_query": query,
            "api_key": SERPAPI_API_KEY
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            videos = data.get('video_results', [])

            for video in videos[:max_results]:
                video['source'] = 'search'
            all_videos.extend(videos[:max_results])

        return all_videos

    except Exception as e:
        print(f"Error searching videos: {e}")
        return all_videos

def fetch_channel_videos_sorted(channel_name, sort_mode='oldest', max_pages=20):
    """Fetch channel videos sorted by upload date (oldest or newest)"""
    all_videos = []
    seen_video_ids = set()

    try:
        import time
        url = "https://serpapi.com/search.json"

        # sp parameter for sorting:
        # CAI= for newest (upload date)
        # CAISAhAB= for oldest (upload date reversed)
        sp_param = "CAISAhAB" if sort_mode == 'oldest' else "CAI%3D"

        params = {
            "engine": "youtube",
            "search_query": f'"{channel_name}"',
            "api_key": SERPAPI_API_KEY,
            "sp": sp_param
        }

        page_count = 0
        while page_count < max_pages:
            page_count += 1
            print(f"Sorted search ({sort_mode}) page {page_count} for: {channel_name[:30]}...")

            response = requests.get(url, params=params, timeout=60)

            if response.status_code != 200:
                print(f"Sorted search API error: {response.status_code}")
                break

            data = response.json()
            videos = data.get('video_results', [])

            if not videos:
                print("No more videos in sorted search")
                break

            new_count = 0
            for video in videos:
                video_id = video.get('link', '')
                video_channel = video.get('channel', {})
                video_channel_name = video_channel.get('name', '') if isinstance(video_channel, dict) else str(video_channel)

                # Check if this is from the right channel
                if channel_name.lower() in video_channel_name.lower() or video_channel_name.lower() in channel_name.lower():
                    if video_id and video_id not in seen_video_ids:
                        seen_video_ids.add(video_id)
                        video['source'] = f'sorted_{sort_mode}'
                        all_videos.append(video)
                        new_count += 1

            print(f"Added {new_count} videos from sorted search (total: {len(all_videos)})")

            if new_count == 0:
                break

            # Get next page token
            serpapi_pagination = data.get('serpapi_pagination', {})
            next_page_token = serpapi_pagination.get('next_page_token')

            if not next_page_token:
                break

            params['sp'] = next_page_token
            time.sleep(0.3)

        return all_videos

    except Exception as e:
        print(f"Error in sorted search: {e}")
        return all_videos

def search_competitor_website(competitor):
    """Search for competitor website content keywords"""
    try:
        if not SERPAPI_API_KEY:
            return {'success': False, 'error': 'SerpAPI key not configured'}

        # Search Google for the competitor's site
        url = "https://serpapi.com/search.json"
        params = {
            "engine": "google",
            "q": f"site:{competitor}",
            "api_key": SERPAPI_API_KEY,
            "num": 20
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            organic = data.get('organic_results', [])

            keywords = []
            for result in organic:
                title = result.get('title', '')
                # Extract potential keywords from titles
                keywords.extend(extract_keywords_from_title(title))

            return {'success': True, 'keywords': list(set(keywords))}
        else:
            return {'success': False, 'error': f"SerpAPI error: {response.status_code}"}

    except Exception as e:
        return {'success': False, 'error': str(e)}

def extract_keywords_from_videos(videos):
    """Extract potential keywords from video titles - returns both per-video and aggregated"""
    keywords = []
    seen = set()
    video_keywords = []  # Full list with each video's target keyword

    for video in videos:
        title = video.get('title', '')
        # Handle both nested and flat channel structures
        if isinstance(video.get('channel'), dict):
            channel = video.get('channel', {}).get('name', '')
        else:
            channel = video.get('channel', '')
        views = video.get('views', '')
        link = video.get('link', '')
        published = video.get('published_date', video.get('published', ''))

        # Extract the PRIMARY target keyword from title
        primary_keyword = extract_primary_keyword(title)

        # Store video with its target keyword
        video_keywords.append({
            'title': title,
            'channel': channel,
            'views': views,
            'link': link,
            'published': published,
            'target_keyword': primary_keyword
        })

        # Also extract all keyword patterns for aggregation
        extracted = extract_keywords_from_title(title)

        for kw in extracted:
            kw_lower = kw.lower()
            if kw_lower not in seen and len(kw) > 3:
                seen.add(kw_lower)
                keywords.append({
                    'keyword': kw,
                    'source_video': title,
                    'source_channel': channel,
                    'source_views': views
                })

    return keywords, video_keywords

def extract_primary_keyword(title):
    """Extract the PRIMARY target keyword from a video title"""
    import re

    # Clean title
    title_clean = title.lower().strip()

    # Remove common YouTube title patterns at the end
    title_clean = re.sub(r'\s*[\|\-\[\(].*$', '', title_clean)
    title_clean = re.sub(r'\s*\d{4}$', '', title_clean)  # Remove year at end
    title_clean = re.sub(r'^\d+\.\s*', '', title_clean)  # Remove numbering

    # Priority patterns to extract (ordered by intent value)
    patterns = [
        (r'^([\w\s]+)\s+vs\.?\s+([\w\s]+)(?:\s|$)', 'comparison'),  # "X vs Y"
        (r'^([\w\s]+)\s+review$', 'review'),  # "X review"
        (r'^best\s+([\w\s]+?)(?:\s+for|\s+in|\s+of|\s+\d{4}|$)', 'best_of'),  # "best X"
        (r'^([\w\s]+)\s+(?:coupon|discount|promo|deal)', 'deal'),  # "X coupon"
        (r'^how\s+to\s+([\w\s]+)', 'how_to'),  # "how to X"
        (r'^([\w\s]+)\s+tutorial', 'tutorial'),  # "X tutorial"
        (r'^([\w\s]+)\s+guide', 'guide'),  # "X guide"
        (r'^is\s+([\w\s]+)\s+(?:worth|legit|safe|good)', 'review'),  # "is X worth it"
    ]

    for pattern, kw_type in patterns:
        match = re.search(pattern, title_clean)
        if match:
            # For comparison, return full "X vs Y"
            if kw_type == 'comparison':
                return f"{match.group(1).strip()} vs {match.group(2).strip()}"
            elif kw_type == 'review':
                return f"{match.group(1).strip()} review"
            elif kw_type == 'best_of':
                return f"best {match.group(1).strip()}"
            elif kw_type == 'deal':
                return f"{match.group(1).strip()} coupon"
            else:
                return match.group(1).strip() if match.groups() else title_clean[:50]

    # Fallback: return cleaned title (truncated)
    return title_clean[:60].strip()

def extract_keywords_from_title(title):
    """Extract potential keywords from a title"""
    import re

    keywords = []

    # Clean the title
    title_clean = title.lower()

    # Common patterns to extract
    patterns = [
        r'best\s+[\w\s]+(%s:for|in|of|\d{4})',  # "best X for Y" or "best X 2024"
        r'[\w\s]+\s+vs\.?\s+[\w\s]+',  # "X vs Y"
        r'[\w\s]+\s+review',  # "X review"
        r'[\w\s]+\s+reviews',  # "X reviews"
        r'how\s+to\s+[\w\s]+',  # "how to X"
        r'[\w\s]+\s+coupon(?:\s+code)?',  # "X coupon code"
        r'[\w\s]+\s+discount',  # "X discount"
        r'[\w\s]+\s+tutorial',  # "X tutorial"
        r'[\w\s]+\s+guide',  # "X guide"
    ]

    for pattern in patterns:
        matches = re.findall(pattern, title_clean)
        for match in matches:
            clean_match = match.strip()
            if len(clean_match) > 5 and len(clean_match) < 60:
                keywords.append(clean_match)

    # Also add the full title as a potential keyword if it's reasonable length
    if 10 < len(title) < 60:
        # Remove common YouTube title additions
        clean_title = re.sub(r'\s*[\|\-\[\(].*$', '', title)
        clean_title = re.sub(r'^\d+\.\s*', '', clean_title)
        if clean_title and len(clean_title) > 10:
            keywords.append(clean_title.strip())

    return keywords

def enrich_competitor_keywords(keywords, niche):
    """Add volume data and metrics to extracted keywords"""
    enriched = []

    # Get list of keyword strings
    if isinstance(keywords[0], dict) if keywords else False:
        kw_list = [k.get('keyword', k) for k in keywords]
        kw_metadata = {k.get('keyword', ''): k for k in keywords}
    else:
        kw_list = keywords
        kw_metadata = {}

    # Get volume data from Ahrefs (primary) or Keywords Everywhere (fallback)
    volume_data = get_keyword_data_with_fallback(kw_list[:20])  # Limit API calls
    volume_map = {}
    if volume_data.get('success') and volume_data.get('data'):
        for item in volume_data['data']:
            volume_map[item.get('keyword', '').lower()] = item

    for kw in kw_list[:30]:
        kw_lower = kw.lower() if isinstance(kw, str) else kw.get('keyword', '').lower()
        vol_info = volume_map.get(kw_lower, {})

        volume = vol_info.get('vol', 0)
        cpc = vol_info.get('cpc', {})
        if isinstance(cpc, dict):
            cpc = cpc.get('value', 0)
        competition = vol_info.get('competition', 0)

        # Get metadata if available
        metadata = kw_metadata.get(kw, {})

        # Calculate revenue potential
        revenue_data = estimate_revenue_potential(
            {'volume': volume, 'cpc': cpc},
            {'view_pattern': 'no_data', 'video_count': 10},
            niche,
            keyword=kw if isinstance(kw, str) else kw.get('keyword', '')
        )

        # Calculate priority score
        score = calculate_opportunity_score(
            {'volume': volume, 'keyword_difficulty': competition * 100},
            {'view_pattern': 'no_data', 'avg_views': 0}
        )

        # Generate recommendation
        recommendation = generate_keyword_recommendation(kw if isinstance(kw, str) else kw.get('keyword', ''), volume, revenue_data)

        enriched.append({
            'keyword': kw if isinstance(kw, str) else kw.get('keyword', ''),
            'volume': volume,
            'cpc': cpc,
            'competition': competition,
            'keyword_type': revenue_data.get('keyword_type', 'other'),
            'revenue_potential': revenue_data.get('moderate', 0),
            'revenue_conservative': revenue_data.get('conservative', 0),
            'revenue_optimistic': revenue_data.get('optimistic', 0),
            'epv': revenue_data.get('epv', 0),
            'priority_score': score,
            'opportunity_tier': determine_tier(score),
            'source_video': metadata.get('source_video', ''),
            'source_channel': metadata.get('source_channel', ''),
            'recommendation': recommendation
        })

    # Filter out low-value keywords
    enriched = [k for k in enriched if k['volume'] > 0 or k['priority_score'] > 30]

    return enriched

def generate_keyword_recommendation(keyword, volume, revenue_data):
    """Generate a recommendation for a keyword"""
    kw_type = revenue_data.get('keyword_type', 'other')
    rev = revenue_data.get('moderate', 0)

    if kw_type == 'deal' and volume > 100:
        return "High-intent deal keyword - prioritize!"
    elif kw_type == 'comparison' and volume > 500:
        return "Strong comparison opportunity"
    elif kw_type == 'review' and volume > 1000:
        return "High-volume review keyword"
    elif kw_type == 'best_of' and volume > 2000:
        return "Popular 'best of' search"
    elif rev > 100:
        return "Good revenue potential"
    elif volume > 5000:
        return "High volume, worth testing"
    else:
        return ""

# ============================================
# DOMINATION SCORE ENDPOINTS
# ============================================

DOMINATION_DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'domination_data.json')
BUNDLED_RANKING_PATH = os.path.join(os.path.dirname(__file__), 'data', 'ranking_results.json')
KEYWORD_TRACKING_PATH = os.path.join(os.path.dirname(__file__), 'data', 'keyword_tracking.json')


def fetch_domination_from_bigquery(keywords):
    """Fetch YouTube SERP ranking data from BigQuery for given keywords.

    Returns dict keyed by lowercase keyword with:
    {top_10, domination_score, positions_owned, scrape_date, search_volume}
    """
    from google.cloud import bigquery as bq

    client = get_bq_client()
    if not client:
        print("[BQ] No BigQuery client available")
        return {}

    if not keywords:
        return {}

    # Build parameterized keyword list
    kw_lower = [kw.lower() for kw in keywords]
    kw_params = [bq.ScalarQueryParameter(f"kw_{i}", "STRING", kw) for i, kw in enumerate(kw_lower)]
    kw_placeholders = ', '.join(f"@kw_{i}" for i in range(len(kw_lower)))

    query = f"""
    SELECT
        Keyword,
        Channel_title,
        Rank,
        Views,
        Video_title,
        Search_Volume,
        Scrape_date,
        competitor_checker
    FROM {BQ_SERP_TABLE}
    WHERE LOWER(Keyword) IN ({kw_placeholders})
      AND Scrape_date = BQ_asia_scrape_date
      AND Rank BETWEEN 1 AND 10
      AND Scrape_date = (
          SELECT Scrape_date FROM (
              SELECT Scrape_date, COUNT(*) as row_cnt
              FROM {BQ_SERP_TABLE}
              WHERE Scrape_date = BQ_asia_scrape_date
                AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
              GROUP BY Scrape_date
              HAVING COUNT(*) > 5000
              ORDER BY Scrape_date DESC
              LIMIT 1
          )
      )
    ORDER BY Keyword, Rank
    """

    job_config = bq.QueryJobConfig(query_parameters=kw_params)

    try:
        rows = client.query(query, job_config=job_config).result()

        # Group by keyword (lowercase key)
        keyword_data = {}
        for row in rows:
            kw_key = row.Keyword.lower() if row.Keyword else ''
            if kw_key not in keyword_data:
                keyword_data[kw_key] = {
                    'top_10': [],
                    'scrape_date': str(row.Scrape_date),
                    'search_volume': row.Search_Volume or 0,
                }

            keyword_data[kw_key]['top_10'].append({
                'channel': row.Channel_title or '',
                'title': row.Video_title or '',
                'views': row.Views or 0,
                'rank': row.Rank,
                'link': '',
            })

        # Calculate domination scores
        WEIGHTS = {1: 50, 2: 25, 3: 15, 4: 5, 5: 5}
        bq_names_lower = {n.lower() for n in ALL_BQ_CHANNEL_NAMES}

        for kw_key, data in keyword_data.items():
            score = 0
            positions_owned = []

            for entry in data['top_10'][:5]:
                rank = entry['rank']
                channel_lower = entry['channel'].lower()
                is_digidom = channel_lower in bq_names_lower
                if is_digidom and rank in WEIGHTS:
                    score += WEIGHTS[rank]
                    positions_owned.append(rank)

            data['domination_score'] = min(score, 100)
            data['positions_owned'] = positions_owned

        print(f"[BQ] Fetched domination data for {len(keyword_data)}/{len(keywords)} keywords")
        return keyword_data

    except Exception as e:
        print(f"[BQ] Query error: {e}")
        return {}


def fetch_domination_history_from_bigquery(keyword, days=90):
    """Fetch historical domination scores for a keyword from BigQuery.

    BigQuery has ~2 years of daily scrapes vs. handful of points in Supabase.
    Returns list of dicts: [{scrape_date, domination_score, positions_owned, search_volume}]
    """
    from google.cloud import bigquery as bq

    client = get_bq_client()
    if not client:
        return []

    ch_names_str = ', '.join(f"'{name}'" for name in ALL_BQ_CHANNEL_NAMES)

    query = f"""
    WITH ranked_data AS (
        SELECT
            Scrape_date,
            Channel_title,
            Rank,
            Search_Volume
        FROM {BQ_SERP_TABLE}
        WHERE LOWER(Keyword) = LOWER(@keyword)
          AND Scrape_date = BQ_asia_scrape_date
          AND Rank BETWEEN 1 AND 5
          AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)
    ),
    daily_scores AS (
        SELECT
            Scrape_date,
            MAX(Search_Volume) as search_volume,
            SUM(CASE
                WHEN Channel_title IN ({ch_names_str}) THEN
                    CASE Rank
                        WHEN 1 THEN 50
                        WHEN 2 THEN 25
                        WHEN 3 THEN 15
                        WHEN 4 THEN 5
                        WHEN 5 THEN 5
                        ELSE 0
                    END
                ELSE 0
            END) as raw_score,
            ARRAY_AGG(
                CASE WHEN Channel_title IN ({ch_names_str}) THEN Rank END
                IGNORE NULLS
            ) as owned_positions
        FROM ranked_data
        GROUP BY Scrape_date
    )
    SELECT
        Scrape_date as scrape_date,
        LEAST(raw_score, 100) as domination_score,
        owned_positions,
        search_volume
    FROM daily_scores
    ORDER BY Scrape_date DESC
    """

    job_config = bq.QueryJobConfig(query_parameters=[
        bq.ScalarQueryParameter("keyword", "STRING", keyword),
        bq.ScalarQueryParameter("days", "INT64", days),
    ])

    try:
        rows = client.query(query, job_config=job_config).result()
        history = []
        for row in rows:
            history.append({
                'scrape_date': str(row.scrape_date),
                'snapshot_date': str(row.scrape_date),
                'domination_score': row.domination_score,
                'positions_owned': list(row.owned_positions) if row.owned_positions else [],
                'search_volume': row.search_volume or 0,
                'revenue': 0,
            })
        return history
    except Exception as e:
        print(f"[BQ] History query error: {e}")
        return []


def load_keyword_tracking():
    """Load the keyword tracking config (silos, groups, secondaries)."""
    try:
        if os.path.exists(KEYWORD_TRACKING_PATH):
            with open(KEYWORD_TRACKING_PATH, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"[TRACKING] Error loading keyword_tracking.json: {e}")
    return None


def get_tracking_keywords_flat():
    """Flatten keyword_tracking.json into a list of all keywords to audit.
    Returns list of dicts: [{keyword, silo, group, is_secondary, revenue}]"""
    config = load_keyword_tracking()
    if not config:
        return []

    # Fetch BQ revenue to override hardcoded JSON values
    bq_revenue = fetch_current_month_revenue_from_bq()

    flat = []
    for silo in config.get('silos', []):
        silo_id = silo['id']
        for group in silo.get('groups', []):
            group_name = group['name']
            for kw_entry in group.get('keywords', []):
                keyword = kw_entry['keyword']
                revenue = bq_revenue.get(keyword.lower(), kw_entry.get('revenue', 0))
                flat.append({
                    'keyword': keyword,
                    'silo': silo_id,
                    'group': group_name,
                    'is_secondary': False,
                    'revenue': revenue
                })
                for sec in kw_entry.get('secondary', []):
                    flat.append({
                        'keyword': sec,
                        'silo': silo_id,
                        'group': group_name,
                        'is_secondary': True,
                        'revenue': 0
                    })
    return flat


def fetch_current_month_revenue_from_bq():
    """Fetch current month revenue per keyword from BQ Metrics_by_Month table.

    Revenue in BQ is per-video per-month, so we SUM across all videos/channels
    for each keyword to get keyword-level revenue.

    Returns dict: {keyword_lower: revenue_float}
    Cached for 30 minutes.
    """
    global _bq_revenue_cache
    now = datetime.now()
    if _bq_revenue_cache['data'] is not None and _bq_revenue_cache['timestamp']:
        age = (now - _bq_revenue_cache['timestamp']).total_seconds()
        if age < BQ_REVENUE_CACHE_TTL:
            return _bq_revenue_cache['data']

    client = get_bq_client()
    if not client:
        print("[BQ] No BigQuery client available for revenue query")
        return {}

    try:
        query = f"""
        SELECT
            LOWER(Video_main_keyword) as keyword,
            SUM(revenue) as total_revenue
        FROM {BQ_METRICS_TABLE}
        WHERE Metrics_month_year = DATE_TRUNC(CURRENT_DATE(), MONTH)
          AND Video_main_keyword IS NOT NULL
          AND Video_main_keyword != ''
        GROUP BY LOWER(Video_main_keyword)
        HAVING SUM(revenue) > 0
        """

        results = {}
        for row in client.query(query).result():
            results[row.keyword] = round(row.total_revenue, 2)

        _bq_revenue_cache['data'] = results
        _bq_revenue_cache['timestamp'] = now
        print(f"[BQ] Cached current month revenue for {len(results)} keywords")
        return results
    except Exception as e:
        print(f"[BQ] Error fetching current month revenue: {e}")
        return _bq_revenue_cache.get('data') or {}


def fetch_daily_revenue_history_from_bq(keyword, days=90):
    """Fetch daily revenue history for a specific keyword from BQ.

    Joins Daily_Rev_Metrics_by_Video_ID with Digibot_General_info
    to map video_id -> main_keyword, then SUMs daily revenue across all videos.

    Returns dict: {date_str: revenue_float} for easy lookup by date.
    """
    from google.cloud import bigquery as bq

    client = get_bq_client()
    if not client:
        return {}

    try:
        query = f"""
        SELECT
            rev.Metrics_date as rev_date,
            SUM(rev.revenue) as daily_revenue
        FROM {BQ_DAILY_REV_TABLE} rev
        LEFT JOIN {BQ_GENERAL_INFO_TABLE} info
          ON rev.video_id = info.video_id
        WHERE LOWER(info.main_keyword) = LOWER(@keyword)
          AND rev.Metrics_date >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)
        GROUP BY rev.Metrics_date
        ORDER BY rev.Metrics_date ASC
        """

        job_config = bq.QueryJobConfig(query_parameters=[
            bq.ScalarQueryParameter("keyword", "STRING", keyword),
            bq.ScalarQueryParameter("days", "INT64", days),
        ])

        results = {}
        for row in client.query(query, job_config=job_config).result():
            results[str(row.rev_date)] = round(row.daily_revenue, 2)
        return results
    except Exception as e:
        print(f"[BQ] Error fetching daily revenue history for '{keyword}': {e}")
        return {}


# ============================================
# PRIORITY KEYWORD MANAGEMENT ENDPOINTS
# ============================================

# In-memory cache for BQ available keywords (avoid repeated BQ queries)
_bq_keywords_cache = {'data': None, 'timestamp': None}
BQ_CACHE_TTL = 3600  # 1 hour

# In-memory cache for BQ revenue data (current month)
_bq_revenue_cache = {'data': None, 'timestamp': None}
BQ_REVENUE_CACHE_TTL = 1800  # 30 min — revenue is monthly, safe to cache

def _get_bq_available_keywords():
    """Fetch distinct tracked keywords from BigQuery (cached 1 hour)."""
    now = datetime.now()
    if _bq_keywords_cache['data'] and _bq_keywords_cache['timestamp']:
        age = (now - _bq_keywords_cache['timestamp']).total_seconds()
        if age < BQ_CACHE_TTL:
            return _bq_keywords_cache['data']

    client = get_bq_client()
    if not client:
        return []

    try:
        q = f"""
        SELECT
            LOWER(Keyword) as keyword,
            MAX(Search_Volume) as search_volume,
            MAX(Silo) as silo,
            MAX(CASE WHEN competitor_checker = 'Digidom' THEN 1 ELSE 0 END) as has_digidom
        FROM {BQ_SERP_TABLE}
        WHERE Scrape_date = BQ_asia_scrape_date
          AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
          AND competitor_checker IS NOT NULL
        GROUP BY LOWER(Keyword)
        ORDER BY keyword
        """
        results = []
        for row in client.query(q).result():
            results.append({
                'keyword': row.keyword,
                'search_volume': row.search_volume or 0,
                'silo': row.silo or '',
                'has_digidom': bool(row.has_digidom),
            })
        _bq_keywords_cache['data'] = results
        _bq_keywords_cache['timestamp'] = now
        print(f"[BQ] Cached {len(results)} available keywords from BigQuery")
        return results
    except Exception as e:
        print(f"[BQ] Error fetching available keywords: {e}")
        return _bq_keywords_cache.get('data') or []


@app.route('/api/keywords/available', methods=['GET'])
@login_required
def get_available_keywords():
    """Get all keywords from DB + any BQ keywords not yet in DB."""
    try:
        # Get all priority_keywords from DB
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT keyword, tier, niche, priority_score, search_volume, source, is_active, added_by, is_primary, parent_keyword FROM priority_keywords ORDER BY priority_score DESC, keyword')
        db_rows = c.fetchall()
        release_db(conn)

        db_keywords = {}
        for row in db_rows:
            db_keywords[row[0]] = {
                'keyword': row[0],
                'tier': row[1] or 'A',
                'niche': row[2] or '',
                'priority_score': row[3] or 0,
                'search_volume': row[4] or 0,
                'source': row[5] or 'csv',
                'is_active': row[6],
                'added_by': row[7] or 'system',
                'in_bigquery': False,
                'is_primary': row[8] if row[8] is not None else False,
                'parent_keyword': row[9] or '',
            }

        # Get BQ keywords and merge
        bq_keywords = _get_bq_available_keywords()
        for bq in bq_keywords:
            kw = bq['keyword']
            if kw in db_keywords:
                db_keywords[kw]['in_bigquery'] = True
                if bq['search_volume'] > db_keywords[kw]['search_volume']:
                    db_keywords[kw]['search_volume'] = bq['search_volume']
            else:
                db_keywords[kw] = {
                    'keyword': kw,
                    'tier': '',
                    'niche': bq.get('silo', ''),
                    'priority_score': 0,
                    'search_volume': bq['search_volume'],
                    'source': 'bigquery',
                    'is_active': False,
                    'added_by': '',
                    'in_bigquery': True,
                    'is_primary': False,
                    'parent_keyword': '',
                }

        # Build primary/secondary mappings from keyword_tracking.json
        sec_to_primary = {}
        primary_to_sec = {}
        primary_set = set()
        try:
            _tk_path = os.path.join(os.path.dirname(__file__), 'data', 'keyword_tracking.json')
            if os.path.exists(_tk_path):
                with open(_tk_path) as _f:
                    _tk = json.load(_f)
                for _silo in _tk.get('silos', []):
                    for _grp in _silo.get('groups', []):
                        for _ke in _grp.get('keywords', []):
                            _pk = _ke['keyword'].lower().strip()
                            primary_set.add(_pk)
                            secs = []
                            for _s in _ke.get('secondary', []):
                                _sk = _s.lower().strip()
                                secs.append(_sk)
                                if _sk not in sec_to_primary:
                                    sec_to_primary[_sk] = []
                                sec_to_primary[_sk].append(_pk)
                            primary_to_sec[_pk] = secs
        except Exception:
            pass

        # Also build reverse map from DB-stored parent_keyword relationships
        for kw_data in db_keywords.values():
            pk = kw_data.get('parent_keyword', '')
            if pk and pk in db_keywords:
                if pk not in primary_to_sec:
                    primary_to_sec[pk] = []
                if kw_data['keyword'] not in primary_to_sec[pk]:
                    primary_to_sec[pk].append(kw_data['keyword'])
                if kw_data['keyword'] not in sec_to_primary:
                    sec_to_primary[kw_data['keyword']] = []
                if pk not in sec_to_primary[kw_data['keyword']]:
                    sec_to_primary[kw_data['keyword']].append(pk)

        for kw_data in db_keywords.values():
            kw = kw_data['keyword']
            kw_data['secondary_of'] = sec_to_primary.get(kw, [])
            kw_data['secondaries'] = primary_to_sec.get(kw, [])
            # Use DB is_primary if set, otherwise infer from tracking JSON
            if not kw_data['is_primary']:
                kw_data['is_primary'] = kw in primary_set

        all_kw = sorted(db_keywords.values(), key=lambda x: (-x['is_active'], -x['priority_score'], x['keyword']))
        active_count = sum(1 for k in all_kw if k['is_active'])

        return jsonify({
            'success': True,
            'keywords': all_kw,
            'total': len(all_kw),
            'active_count': active_count,
        })
    except Exception as e:
        print(f"[API] Error in get_available_keywords: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/keywords/priority', methods=['GET'])
@login_required
def get_priority_keywords():
    """Get active priority keywords only."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT keyword, tier, niche, priority_score, search_volume, source FROM priority_keywords WHERE is_active = TRUE ORDER BY priority_score DESC, keyword')
        rows = c.fetchall()
        release_db(conn)

        keywords = [{
            'keyword': r[0], 'tier': r[1], 'niche': r[2],
            'priority_score': r[3], 'search_volume': r[4], 'source': r[5]
        } for r in rows]

        return jsonify({'success': True, 'keywords': keywords, 'count': len(keywords)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/keywords/priority/toggle', methods=['PUT'])
@login_required
def toggle_priority_keywords():
    """Toggle keywords active/inactive. For BQ keywords not in DB, inserts them."""
    data = request.get_json()
    keywords = data.get('keywords', [])
    active = data.get('active', True)
    user = get_current_user()
    email = user.get('email', 'unknown') if user else 'unknown'

    if not keywords:
        return jsonify({'success': False, 'error': 'No keywords provided'}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        updated = 0
        inserted = 0
        for kw in keywords:
            kw_lower = kw.lower().strip()
            if not kw_lower:
                continue
            # Try update first (block deactivating primary keywords that have secondaries)
            if not active:
                c.execute("""UPDATE priority_keywords SET is_active = %s WHERE keyword = %s
                    AND NOT (is_primary = TRUE AND EXISTS (
                        SELECT 1 FROM priority_keywords sk WHERE sk.parent_keyword = priority_keywords.keyword AND sk.parent_keyword != ''
                    ))""", (active, kw_lower))
            else:
                c.execute('UPDATE priority_keywords SET is_active = %s WHERE keyword = %s', (active, kw_lower))
            if c.rowcount > 0:
                updated += 1
            else:
                # Not in DB yet (BQ keyword) — insert it
                c.execute('''
                    INSERT INTO priority_keywords (keyword, tier, source, is_active, added_by)
                    VALUES (%s, '', 'bigquery', %s, %s)
                    ON CONFLICT (keyword) DO UPDATE SET is_active = %s
                ''', (kw_lower, active, email, active))
                inserted += 1
        conn.commit()
        release_db(conn)
        return jsonify({'success': True, 'updated': updated, 'inserted': inserted})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/keywords/priority/custom', methods=['POST'])
@login_required
def add_custom_keyword():
    """Add a user-typed custom keyword with optional primary/secondary role."""
    data = request.get_json()
    keyword = (data.get('keyword', '') or '').lower().strip()
    role = data.get('role', 'none')  # 'primary', 'secondary', or 'none'
    parent_keyword = (data.get('parent_keyword', '') or '').lower().strip()
    silo = (data.get('silo', '') or '').strip()
    user = get_current_user()
    email = user.get('email', 'unknown') if user else 'unknown'

    if not keyword or len(keyword) < 2:
        return jsonify({'success': False, 'error': 'Keyword too short'}), 400

    # Map silo IDs to niche labels
    silo_to_niche = {
        'id_theft': 'ID Theft', 'dog': 'Dog',
        'data_broker': 'Data Broker', 'parental_control': 'Parental Control',
        'new': ''
    }

    is_primary = role == 'primary'
    parent_kw = parent_keyword if role == 'secondary' else ''

    try:
        conn = get_db()
        c = conn.cursor()

        # If secondary, inherit tier/niche from parent
        tier = 'custom'
        niche = silo_to_niche.get(silo, silo) if silo else ''
        priority_score = 0
        if parent_kw:
            c.execute('SELECT tier, niche, priority_score FROM priority_keywords WHERE keyword = %s', (parent_kw,))
            parent_row = c.fetchone()
            if parent_row:
                tier = parent_row[0] or 'custom'
                niche = parent_row[1] or ''
                priority_score = (parent_row[2] or 0) * 0.9  # secondary gets 90% of parent score

        c.execute('''
            INSERT INTO priority_keywords (keyword, tier, niche, priority_score, source, is_active, added_by, is_primary, parent_keyword)
            VALUES (%s, %s, %s, %s, 'custom', TRUE, %s, %s, %s)
            ON CONFLICT (keyword) DO UPDATE SET is_active = TRUE, source = 'custom', added_by = %s, is_primary = %s, parent_keyword = %s
        ''', (keyword, tier, niche, priority_score, email, is_primary, parent_kw, email, is_primary, parent_kw))
        conn.commit()
        release_db(conn)
        return jsonify({
            'success': True, 'keyword': keyword,
            'tier': tier, 'niche': niche, 'priority_score': priority_score,
            'is_primary': is_primary, 'parent_keyword': parent_kw
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/keywords/priority', methods=['DELETE'])
@login_required
def delete_priority_keywords():
    """Hard-delete keywords from priority list."""
    data = request.get_json()
    keywords = data.get('keywords', [])

    if not keywords:
        return jsonify({'success': False, 'error': 'No keywords provided'}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        kw_lower = [kw.lower().strip() for kw in keywords if kw.strip()]

        # Check if any primary keywords have secondaries
        c.execute("""
            SELECT pk.keyword, COUNT(sk.keyword) as sec_count
            FROM priority_keywords pk
            LEFT JOIN priority_keywords sk ON sk.parent_keyword = pk.keyword AND sk.parent_keyword != ''
            WHERE pk.keyword = ANY(%s) AND pk.is_primary = TRUE
            GROUP BY pk.keyword
            HAVING COUNT(sk.keyword) > 0
        """, (kw_lower,))
        blocked = c.fetchall()
        if blocked:
            blocked_list = [f"{row[0]} ({row[1]} secondaries)" for row in blocked]
            release_db(conn)
            return jsonify({'success': False, 'error': f"Cannot delete primary keywords with secondaries: {', '.join(blocked_list)}. Remove secondaries first."}), 400

        c.execute('DELETE FROM priority_keywords WHERE keyword = ANY(%s)', (kw_lower,))
        deleted = c.rowcount
        conn.commit()
        release_db(conn)
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/keywords/priority/roles', methods=['PUT'])
@login_required
def update_keyword_roles():
    """Update primary/secondary roles for keywords."""
    data = request.get_json()
    roles = data.get('roles', [])  # [{keyword, role, parent_keyword}, ...]

    if not roles:
        return jsonify({'success': True, 'updated': 0})

    silo_to_niche = {
        'id_theft': 'ID Theft', 'dog': 'Dog',
        'data_broker': 'Data Broker', 'parental_control': 'Parental Control',
        'new': ''
    }

    try:
        conn = get_db()
        c = conn.cursor()
        updated = 0
        for r in roles:
            kw = (r.get('keyword', '') or '').lower().strip()
            role = r.get('role', 'none')
            parent = (r.get('parent_keyword', '') or '').lower().strip()
            silo = r.get('silo', '')
            niche = silo_to_niche.get(silo, silo) if silo else None
            if not kw:
                continue

            is_primary = role == 'primary'
            parent_kw = parent if role == 'secondary' else ''

            # If secondary, inherit tier/niche from parent
            if parent_kw:
                c.execute('SELECT tier, niche, priority_score FROM priority_keywords WHERE keyword = %s', (parent_kw,))
                prow = c.fetchone()
                if prow:
                    c.execute('UPDATE priority_keywords SET is_primary = %s, parent_keyword = %s, tier = %s, niche = %s, priority_score = %s WHERE keyword = %s',
                              (is_primary, parent_kw, prow[0] or '', prow[1] or '', (prow[2] or 0) * 0.9, kw))
                    updated += c.rowcount
                    continue

            # Update role and optionally niche/silo
            if niche is not None:
                c.execute('UPDATE priority_keywords SET is_primary = %s, parent_keyword = %s, niche = %s WHERE keyword = %s',
                          (is_primary, parent_kw, niche, kw))
            else:
                c.execute('UPDATE priority_keywords SET is_primary = %s, parent_keyword = %s WHERE keyword = %s',
                          (is_primary, parent_kw, kw))
            # If set as primary, ensure it's active
            if is_primary:
                c.execute('UPDATE priority_keywords SET is_active = TRUE WHERE keyword = %s', (kw,))
            updated += c.rowcount

        conn.commit()
        release_db(conn)
        return jsonify({'success': True, 'updated': updated})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domination/data', methods=['GET'])
@login_required
def get_domination_data():
    """Get domination data merged with tracking config, audit results, and targets."""
    try:
        # 1. Load audit results (local file → DB → bundled fallback)
        audit_data = None
        source = 'none'

        if os.path.exists(DOMINATION_DATA_PATH):
            with open(DOMINATION_DATA_PATH, 'r') as f:
                audit_data = json.load(f)
            source = 'local'

        if not audit_data:
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute('SELECT audit_json, created_at FROM domination_audits ORDER BY created_at DESC LIMIT 1')
                row = c.fetchone()
                release_db(conn)
                if row and row[0]:
                    audit_data = json.loads(row[0])
                    source = 'database'
            except Exception as db_err:
                print(f"[DOMINATION] Postgres fallback error: {db_err}")
                # Try REST API
                try:
                    rows = supabase_rest_select('domination_audits', select='audit_json,created_at',
                                                 order='created_at.desc', limit=1)
                    if rows and rows[0].get('audit_json'):
                        audit_data = json.loads(rows[0]['audit_json'])
                        source = 'rest_api'
                except Exception as rest_err:
                    print(f"[DOMINATION] REST API fallback error: {rest_err}")

        if not audit_data and os.path.exists(BUNDLED_RANKING_PATH):
            with open(BUNDLED_RANKING_PATH, 'r') as f:
                audit_data = json.load(f)
            source = 'bundled'

        # 2. Load tracking config (silos/groups/secondaries) and merge with priority DB
        tracking = load_keyword_tracking()

        # 2b. Merge active priority keywords from DB that aren't in tracking config
        try:
            conn2 = get_db()
            c2 = conn2.cursor()
            c2.execute("""
                SELECT keyword, is_primary, parent_keyword, tier, niche, priority_score
                FROM priority_keywords
                WHERE is_active = TRUE
            """)
            db_keywords = c2.fetchall()
            conn2.close()

            # Build set of keywords already in tracking config
            tracking_kws = set()
            if tracking and tracking.get('silos'):
                for silo in tracking['silos']:
                    for group in silo.get('groups', []):
                        for kw_entry in group.get('keywords', []):
                            tracking_kws.add(kw_entry['keyword'])
                            for sec in kw_entry.get('secondary', []):
                                tracking_kws.add(sec)

            # Find primary keywords not in tracking
            new_primaries = []
            new_secondaries = {}  # parent -> [secondary keywords]
            for row in db_keywords:
                kw, is_primary, parent_kw, tier, niche, score = row
                if kw not in tracking_kws:
                    if is_primary:
                        new_primaries.append({
                            'keyword': kw, 'tier': tier, 'niche': niche or '',
                            'priority_score': score or 0, 'revenue': 0, 'secondary': []
                        })
                    elif parent_kw:
                        new_secondaries.setdefault(parent_kw, []).append(kw)

            # Attach secondaries to their new primaries
            for p in new_primaries:
                p['secondary'] = new_secondaries.get(p['keyword'], [])

            # Also attach secondaries to existing tracking primaries
            if tracking and tracking.get('silos'):
                for silo in tracking['silos']:
                    for group in silo.get('groups', []):
                        for kw_entry in group.get('keywords', []):
                            extra_secs = new_secondaries.get(kw_entry['keyword'], [])
                            if extra_secs:
                                existing = kw_entry.get('secondary', [])
                                kw_entry['secondary'] = existing + [s for s in extra_secs if s not in existing]

            # Add new primaries as a new silo if any exist
            if new_primaries:
                # Group by niche
                niche_groups = {}
                for p in new_primaries:
                    niche = p.get('niche') or 'Unassigned'
                    niche_groups.setdefault(niche, []).append(p)

                new_silo = {
                    'id': 'new_keywords',
                    'label': 'New Keywords',
                    'groups': []
                }
                for niche, kws in niche_groups.items():
                    new_silo['groups'].append({
                        'name': niche,
                        'keywords': kws
                    })

                if not tracking:
                    tracking = {'silos': []}
                if not tracking.get('silos'):
                    tracking['silos'] = []
                tracking['silos'].append(new_silo)

        except Exception as e:
            print(f"[DOMINATION] Error merging priority keywords: {e}")

        # 3. Load target scores from DB
        targets = {}
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('SELECT keyword, target_dom_score, updated_by, updated_at FROM keyword_dom_targets')
            for row in c.fetchall():
                targets[row[0]] = {
                    'target': row[1],
                    'updated_by': row[2],
                    'updated_at': str(row[3]) if row[3] else None
                }
            release_db(conn)
        except Exception as e:
            print(f"[DOMINATION] Error loading targets: {e}")

        # 4. Build index of audit results by keyword for fast lookup
        audit_results_by_kw = {}
        if audit_data:
            for result in audit_data.get('all_results', []):
                kw = result.get('keyword', '')
                if kw:
                    audit_results_by_kw[kw] = result

            # Also index ranking/not_ranking for revenue
            for item in audit_data.get('ranking', []):
                kw = item.get('keyword', '')
                if kw and kw in audit_results_by_kw:
                    audit_results_by_kw[kw]['_is_ranking'] = True
                    audit_results_by_kw[kw]['_revenue'] = item.get('revenue', 0)
            for item in audit_data.get('not_ranking', []):
                kw = item.get('keyword', '')
                if kw and kw in audit_results_by_kw:
                    audit_results_by_kw[kw]['_is_ranking'] = False
                    audit_results_by_kw[kw]['_revenue'] = item.get('revenue', 0)

        # 5. Fetch current month revenue from BigQuery (replaces hardcoded JSON values)
        bq_revenue = fetch_current_month_revenue_from_bq()
        if bq_revenue and tracking and tracking.get('silos'):
            for silo in tracking['silos']:
                for group in silo.get('groups', []):
                    for kw_entry in group.get('keywords', []):
                        kw_lower = kw_entry['keyword'].lower()
                        if kw_lower in bq_revenue:
                            kw_entry['revenue'] = bq_revenue[kw_lower]

        # 6. Return combined response
        return jsonify({
            'success': True,
            'source': source,
            'tracking': tracking,
            'targets': targets,
            'audit_data': audit_data,
            'audit_results_by_keyword': audit_results_by_kw,
            'timestamp': audit_data.get('timestamp') if audit_data else None,
            'revenue_source': 'bigquery' if bq_revenue else 'config'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/domination/targets', methods=['GET'])
@login_required
def get_domination_targets():
    """Get all keyword target dom scores."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT keyword, target_dom_score, updated_by, updated_at FROM keyword_dom_targets')
        rows = c.fetchall()
        release_db(conn)
        targets = {row[0]: {'target': row[1], 'updated_by': row[2], 'updated_at': str(row[3]) if row[3] else None} for row in rows}
        return jsonify({'success': True, 'targets': targets})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domination/targets', methods=['PUT'])
@login_required
def set_domination_target():
    """Set target dom score for a keyword. Tracks who made the change."""
    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()
        target = data.get('target_dom_score', 100)

        if not keyword:
            return jsonify({'success': False, 'error': 'keyword is required'}), 400
        if not isinstance(target, (int, float)) or target < 0 or target > 100:
            return jsonify({'success': False, 'error': 'target_dom_score must be 0-100'}), 400

        user = get_current_user()
        updated_by = user.get('email', 'unknown') if user else 'unknown'

        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO keyword_dom_targets (keyword, target_dom_score, updated_by, updated_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (keyword) DO UPDATE SET
                target_dom_score = EXCLUDED.target_dom_score,
                updated_by = EXCLUDED.updated_by,
                updated_at = NOW()
        ''', (keyword, int(target), updated_by))
        conn.commit()
        release_db(conn)

        return jsonify({'success': True, 'keyword': keyword, 'target_dom_score': int(target), 'updated_by': updated_by})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domination/data', methods=['POST'])
def save_domination_data():
    """Save domination/ranking data from check_rankings.py"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        # Ensure data directory exists
        os.makedirs(os.path.dirname(DOMINATION_DATA_PATH), exist_ok=True)

        # Save to file
        with open(DOMINATION_DATA_PATH, 'w') as f:
            json.dump(data, f, indent=2)

        # Also store in database for historical tracking
        store_ranking_snapshot(data)

        return jsonify({'success': True, 'message': 'Data saved successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def store_ranking_snapshot(data):
    """Store ranking data snapshot in database for historical tracking.
    Also stores full audit JSON for retrieval when local files are unavailable."""
    try:
        conn = get_db()
        c = conn.cursor()

        # Create tables if not exists
        c.execute('''
            CREATE TABLE IF NOT EXISTS ranking_history (
                id SERIAL PRIMARY KEY,
                keyword TEXT NOT NULL,
                revenue DOUBLE PRECISION,
                domination_score DOUBLE PRECISION,
                positions_owned TEXT,
                snapshot_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS domination_audits (
                id SERIAL PRIMARY KEY,
                audit_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Store each keyword's ranking data
        timestamp = data.get('timestamp', datetime.now().isoformat())

        for result in data.get('all_results', []):
            if result.get('error'):
                continue

            keyword = result.get('keyword', '')

            # Find revenue
            kw_info = None
            for r in data.get('ranking', []):
                if r.get('keyword') == keyword:
                    kw_info = r
                    break
            if not kw_info:
                for r in data.get('not_ranking', []):
                    if r.get('keyword') == keyword:
                        kw_info = r
                        break

            revenue = kw_info.get('revenue', 0) if kw_info else 0

            # Calculate domination score
            score, positions_owned = calculate_domination_from_result(result)

            c.execute('''
                INSERT INTO ranking_history (keyword, revenue, domination_score, positions_owned, snapshot_date)
                VALUES (%s, %s, %s, %s, %s)
            ''', (keyword, revenue, score, json.dumps(positions_owned), timestamp))

        # Store full audit JSON for retrieval (keep only last 10 audits)
        c.execute('INSERT INTO domination_audits (audit_json) VALUES (%s)', (json.dumps(data),))
        c.execute('''
            DELETE FROM domination_audits
            WHERE id NOT IN (SELECT id FROM domination_audits ORDER BY created_at DESC LIMIT 10)
        ''')

        conn.commit()
        release_db(conn)
        print(f"[AUDIT] Snapshot stored in DB ({len(data.get('all_results', []))} keywords)")
    except Exception as e:
        print(f"[AUDIT] Postgres store failed: {e}, trying REST API...")
        # Fallback: store via Supabase REST API
        try:
            timestamp = data.get('timestamp', datetime.now().isoformat())
            # Store ranking history rows
            history_rows = []
            for result in data.get('all_results', []):
                if result.get('error'):
                    continue
                keyword = result.get('keyword', '')
                kw_info = None
                for r in data.get('ranking', []):
                    if r.get('keyword') == keyword:
                        kw_info = r
                        break
                if not kw_info:
                    for r in data.get('not_ranking', []):
                        if r.get('keyword') == keyword:
                            kw_info = r
                            break
                revenue = kw_info.get('revenue', 0) if kw_info else 0
                score, positions_owned = calculate_domination_from_result(result)
                history_rows.append({
                    'keyword': keyword, 'revenue': revenue,
                    'domination_score': score,
                    'positions_owned': json.dumps(positions_owned),
                    'snapshot_date': timestamp
                })

            if history_rows:
                # Insert in batches of 100
                for i in range(0, len(history_rows), 100):
                    supabase_rest_insert('ranking_history', history_rows[i:i+100])

            # Store full audit JSON
            supabase_rest_insert('domination_audits', [{'audit_json': json.dumps(data)}])
            print(f"[AUDIT] Snapshot stored via REST API ({len(history_rows)} keywords)")
        except Exception as rest_err:
            print(f"[AUDIT] REST API store also failed: {rest_err}")

def calculate_domination_from_result(result):
    """Calculate domination score from a keyword result"""
    WEIGHTS = {1: 50, 2: 25, 3: 15, 4: 5, 5: 5}

    score = 0
    positions_owned = []

    top_10 = result.get('top_10', [])
    for i in range(min(5, len(top_10))):
        video = top_10[i]
        channel = video.get('channel', '').lower()

        for pattern in ALL_MATCH_PATTERNS:
            if pattern in channel:
                pos = i + 1
                score += WEIGHTS[pos]
                positions_owned.append(pos)
                break

    return min(score, 100), positions_owned

@app.route('/api/domination/audit', methods=['POST'])
def run_domination_audit():
    """Run a domination score audit using BigQuery data.
    Accepts logged-in users (session) or CRON_SECRET for scheduled jobs."""
    # Allow access if logged in OR if valid cron secret provided
    cron_secret = os.environ.get('CRON_SECRET', '')
    provided_secret = request.headers.get('X-Cron-Secret', '') or request.args.get('secret', '')
    has_valid_secret = not cron_secret or provided_secret == cron_secret

    # Check session-based login (same logic as @login_required)
    skip_auth = not os.environ.get('GOOGLE_CLIENT_ID')
    is_logged_in = skip_auth or 'user' in session

    if not is_logged_in and not has_valid_secret:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    # Run the BigQuery-based audit in background
    run_domination_audit_job()

    return jsonify({
        'success': True,
        'message': 'BigQuery audit started in background',
        'status': 'processing'
    })

# Your channel names for audit matching (uses central registry)
YOUR_CHANNELS_LIST = ALL_MATCH_PATTERNS

def check_youtube_ranking(keyword):
    """DEPRECATED for domination scoring (now uses BigQuery).
    Still used by YouTube research features.
    Check YouTube ranking for a single keyword via SerpAPI."""
    try:
        if not SERPAPI_API_KEY:
            return {'error': 'SerpAPI key not configured'}

        url = "https://serpapi.com/search.json"
        params = {
            "engine": "youtube",
            "search_query": keyword,
            "api_key": SERPAPI_API_KEY
        }

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            videos = data.get('video_results', [])

            top_10 = []
            for video in videos[:10]:
                top_10.append({
                    'title': video.get('title', ''),
                    'channel': video.get('channel', {}).get('name', '') if isinstance(video.get('channel'), dict) else video.get('channel', ''),
                    'views': video.get('views', ''),
                    'link': video.get('link', '')
                })

            return {'top_10': top_10}
        else:
            return {'error': f"SerpAPI error: {response.status_code}"}

    except Exception as e:
        return {'error': str(e)}

@app.route('/api/domination/history')
@login_required
def get_domination_history():
    """Get historical domination data. Primary: BigQuery (~2yr daily). Fallback: Supabase."""
    try:
        keyword = request.args.get('keyword', '')
        days = int(request.args.get('days', 90))

        if keyword:
            # Try BigQuery first (much richer history)
            history = fetch_domination_history_from_bigquery(keyword, days=days)

            if history:
                # Fetch daily revenue from BQ (Daily_Rev joined with General_info)
                daily_rev = fetch_daily_revenue_history_from_bq(keyword, days=days)

                # Assign each daily domination entry its matching daily revenue
                for entry in history:
                    entry['revenue'] = daily_rev.get(entry['scrape_date'], 0)

                return jsonify({
                    'success': True,
                    'source': 'bigquery',
                    'history': history,
                    'total_days': len(history),
                })

        # Fallback: Supabase ranking_history
        conn = get_db()
        c = conn.cursor()

        if keyword:
            c.execute('''
                SELECT keyword, revenue, domination_score, positions_owned, snapshot_date
                FROM ranking_history
                WHERE keyword = %s
                ORDER BY snapshot_date DESC
                LIMIT %s
            ''', (keyword, days))
        else:
            c.execute('''
                SELECT keyword, revenue, domination_score, positions_owned, snapshot_date
                FROM ranking_history
                ORDER BY snapshot_date DESC
                LIMIT 100
            ''')

        rows = c.fetchall()
        release_db(conn)

        history = [{
            'keyword': row[0],
            'revenue': row[1],
            'domination_score': row[2],
            'positions_owned': json.loads(row[3]) if row[3] else [],
            'snapshot_date': row[4]
        } for row in rows]

        return jsonify({'success': True, 'source': 'supabase', 'history': history})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# CRON: COLLECT YOUTUBE DATA
# ============================================

# Track background job status
yt_collection_status = {'running': False, 'last_run': None, 'last_results': None}

def collect_yt_data_background(batch_size=50):
    """Background task to collect YT data"""
    import time
    global yt_collection_status

    yt_collection_status['running'] = True
    results = {'processed': 0, 'success': 0, 'failed': 0, 'remaining': 0}

    try:
        conn = get_db()
        c = conn.cursor()

        # Get keywords already in our YT data table
        c.execute('SELECT keyword FROM keyword_yt_data')
        existing_yt_keywords = set(row[0].lower() for row in c.fetchall())

        # Find keywords that need YT data
        keywords_needing_data = []
        for kw in KEYWORDS:
            keyword_lower = kw['keyword'].lower()
            if keyword_lower not in existing_yt_keywords and (not kw.get('ytViews') or kw.get('ytViews') == 0):
                keywords_needing_data.append(kw['keyword'])

        print(f"[CRON-YT] Found {len(keywords_needing_data)} keywords needing YT data")

        keywords_to_process = keywords_needing_data[:batch_size]
        results['remaining'] = len(keywords_needing_data) - len(keywords_to_process)

        for keyword in keywords_to_process:
            try:
                print(f"[CRON-YT] Fetching data for: {keyword}")
                yt_data = get_serpapi_youtube_data(keyword)

                if yt_data.get('success'):
                    top_video = yt_data.get('videos', [{}])[0] if yt_data.get('videos') else {}
                    top_video_title = top_video.get('title', '')
                    top_video_views = parse_view_count(top_video.get('views', '0'))
                    top_video_channel = top_video.get('channel', {}).get('name', '') if isinstance(top_video.get('channel'), dict) else top_video.get('channel', '')

                    c.execute('''
                        INSERT INTO keyword_yt_data
                        (keyword, yt_avg_views, yt_view_pattern, yt_top_video_title,
                         yt_top_video_views, yt_top_video_channel, yt_total_views,
                         yt_video_count, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT (keyword) DO UPDATE SET
                            yt_avg_views = EXCLUDED.yt_avg_views,
                            yt_view_pattern = EXCLUDED.yt_view_pattern,
                            yt_top_video_title = EXCLUDED.yt_top_video_title,
                            yt_top_video_views = EXCLUDED.yt_top_video_views,
                            yt_top_video_channel = EXCLUDED.yt_top_video_channel,
                            yt_total_views = EXCLUDED.yt_total_views,
                            yt_video_count = EXCLUDED.yt_video_count,
                            updated_at = CURRENT_TIMESTAMP
                    ''', (
                        keyword,
                        yt_data.get('avg_views', 0),
                        yt_data.get('view_pattern', 'no_data'),
                        top_video_title,
                        top_video_views,
                        top_video_channel,
                        yt_data.get('total_views', 0),
                        yt_data.get('video_count', 0)
                    ))
                    conn.commit()  # Commit after each to avoid losing progress
                    results['success'] += 1
                else:
                    print(f"[CRON-YT] Failed for {keyword}: {yt_data.get('error')}")
                    results['failed'] += 1

                results['processed'] += 1
                time.sleep(0.3)

            except Exception as e:
                print(f"[CRON-YT] Error processing {keyword}: {e}")
                results['failed'] += 1
                results['processed'] += 1

        release_db(conn)
        print(f"[CRON-YT] Complete: {results}")

    except Exception as e:
        print(f"[CRON-YT] Error: {e}")
        results['error'] = str(e)

    finally:
        yt_collection_status['running'] = False
        yt_collection_status['last_run'] = datetime.now().isoformat()
        yt_collection_status['last_results'] = results

@app.route('/api/cron/collect-yt-data')
def cron_collect_yt_data():
    """
    Cron job to collect YouTube data for keywords missing it.
    Call daily: GET /api/cron/collect-yt-data?secret=YOUR_CRON_SECRET
    Runs in background and returns immediately.
    """
    import threading

    # Verify cron secret
    cron_secret = os.environ.get('CRON_SECRET', '')
    provided_secret = request.args.get('secret', '')

    if cron_secret and provided_secret != cron_secret:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    # Check if already running
    if yt_collection_status['running']:
        return jsonify({
            'success': False,
            'error': 'Collection already in progress',
            'status': yt_collection_status
        })

    # Get batch size from query param (default 50)
    batch_size = min(int(request.args.get('batch', 50)), 100)

    # Run in background thread
    thread = threading.Thread(target=collect_yt_data_background, args=(batch_size,))
    thread.daemon = True
    thread.start()

    return jsonify({
        'success': True,
        'message': f'YT data collection started in background (batch size: {batch_size})',
        'check_status': '/api/cron/yt-status'
    })

@app.route('/api/cron/yt-status')
def cron_yt_status():
    """Check status of YT data collection"""
    try:
        conn = get_db()
        c = conn.cursor()

        c.execute('SELECT COUNT(*) FROM keyword_yt_data')
        collected_count = c.fetchone()[0]

        release_db(conn)

        # Count keywords needing data
        keywords_without_yt = sum(1 for kw in KEYWORDS if not kw.get('ytViews') or kw.get('ytViews') == 0)

        return jsonify({
            'success': True,
            'total_keywords': len(KEYWORDS),
            'keywords_with_yt_in_csv': len(KEYWORDS) - keywords_without_yt,
            'keywords_without_yt_in_csv': keywords_without_yt,
            'collected_in_db': collected_count,
            'still_needed': max(0, keywords_without_yt - collected_count),
            'job_running': yt_collection_status['running'],
            'last_run': yt_collection_status['last_run'],
            'last_results': yt_collection_status['last_results']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GOOGLE TRENDS DATA COLLECTION
# ============================================
trends_collection_status = {
    'running': False,
    'last_run': None,
    'last_results': None
}

# In-memory trends cache — loaded once at startup, updated as trends are collected
# Avoids querying keyword_trends table on every /api/keywords request
TRENDS_CACHE = {}  # {keyword_lower: {trend, trendChange, trendInterest, peakMonths, seasonalityScore, publishWindow}}
TRENDS_CACHE_LOADED = False

def load_trends_cache():
    """Load all trend data from keyword_trends into memory."""
    global TRENDS_CACHE, TRENDS_CACHE_LOADED
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT keyword, trend, trend_change_pct, current_interest, peak_months, seasonality_score, publish_window, updated_at FROM keyword_trends')
        TRENDS_CACHE = {row[0].lower(): {
            'trend': row[1],
            'trendChange': row[2],
            'trendInterest': row[3],
            'peakMonths': row[4],
            'seasonalityScore': row[5] or 0,
            'publishWindow': row[6],
            'trendUpdated': row[7].strftime('%Y-%m-%d') if row[7] else None
        } for row in c.fetchall()}
        release_db(conn)
        TRENDS_CACHE_LOADED = True
        print(f"[TRENDS-CACHE] Loaded {len(TRENDS_CACHE)} cached trends into memory")
    except Exception as e:
        print(f"[TRENDS-CACHE] Failed to load: {e}")

def update_trends_cache(keyword, trend_data):
    """Update a single keyword in the in-memory trends cache."""
    from datetime import date
    TRENDS_CACHE[keyword.lower()] = {
        'trend': trend_data.get('trend', 'unknown'),
        'trendChange': trend_data.get('trend_change_pct', 0),
        'trendInterest': trend_data.get('current_interest', 0),
        'peakMonths': trend_data.get('peak_months'),
        'seasonalityScore': trend_data.get('seasonality_score', 0),
        'publishWindow': trend_data.get('publish_window'),
        'trendUpdated': date.today().strftime('%Y-%m-%d')
    }

# Load trends cache at startup
load_trends_cache()

@app.route('/api/keyword/trend', methods=['POST'])
@login_required
def get_keyword_trend():
    """Fetch Google Trends data for a single keyword and cache it"""
    data = request.get_json()
    keyword = data.get('keyword', '').strip()

    if not keyword:
        return jsonify({'success': False, 'error': 'Keyword is required'}), 400

    try:
        # Check cache first (data less than 7 days old)
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT trend, trend_change_pct, current_interest, data_points, updated_at,
                   peak_months, seasonality_score, publish_window
            FROM keyword_trends WHERE keyword = %s
            AND updated_at > NOW() - INTERVAL '7 days'
        ''', (keyword,))
        cached = c.fetchone()

        if cached:
            release_db(conn)
            return jsonify({
                'success': True,
                'keyword': keyword,
                'trend': cached[0],
                'trend_change_pct': cached[1],
                'current_interest': cached[2],
                'data_points': cached[3],
                'cached': True,
                'updated_at': cached[4],
                'peak_months': cached[5],
                'seasonality_score': cached[6] or 0,
                'publish_window': cached[7]
            })

        # Fetch from SerpAPI
        trend_data = get_serpapi_google_trends(keyword)

        if trend_data.get('success'):
            import json as _json
            c.execute('''
                INSERT INTO keyword_trends (keyword, trend, trend_change_pct, current_interest, data_points,
                    peak_months, low_months, seasonality_score, publish_window, monthly_averages, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT(keyword) DO UPDATE SET
                    trend = EXCLUDED.trend,
                    trend_change_pct = EXCLUDED.trend_change_pct,
                    current_interest = EXCLUDED.current_interest,
                    data_points = EXCLUDED.data_points,
                    peak_months = EXCLUDED.peak_months,
                    low_months = EXCLUDED.low_months,
                    seasonality_score = EXCLUDED.seasonality_score,
                    publish_window = EXCLUDED.publish_window,
                    monthly_averages = EXCLUDED.monthly_averages,
                    updated_at = CURRENT_TIMESTAMP
            ''', (
                keyword,
                trend_data.get('trend', 'unknown'),
                trend_data.get('trend_change_pct', 0),
                trend_data.get('current_interest', 0),
                trend_data.get('data_points', 0),
                trend_data.get('peak_months'),
                trend_data.get('low_months'),
                trend_data.get('seasonality_score', 0),
                trend_data.get('publish_window'),
                _json.dumps(trend_data.get('monthly_averages')) if trend_data.get('monthly_averages') else None
            ))
            conn.commit()
            # Update in-memory cache
            update_trends_cache(keyword, trend_data)

        release_db(conn)

        return jsonify({
            'success': trend_data.get('success', False),
            'keyword': keyword,
            'trend': trend_data.get('trend', 'unknown'),
            'trend_change_pct': trend_data.get('trend_change_pct', 0),
            'current_interest': trend_data.get('current_interest', 0),
            'data_points': trend_data.get('data_points', 0),
            'peak_months': trend_data.get('peak_months'),
            'seasonality_score': trend_data.get('seasonality_score', 0),
            'publish_window': trend_data.get('publish_window'),
            'cached': False,
            'error': trend_data.get('error')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def collect_trends_data_background(batch_size=25):
    """Background task to collect Google Trends data for ALL keywords continuously.
    Processes all remaining keywords in batches, with rate limiting between requests.
    Updates trends_collection_status in real-time for progress tracking."""
    import time as _time
    import json as _json
    global trends_collection_status

    trends_collection_status['running'] = True
    trends_collection_status['stop_requested'] = False
    results = {'processed': 0, 'success': 0, 'failed': 0, 'remaining': 0, 'total': 0}

    try:
        conn = get_db()
        c = conn.cursor()

        # Get keywords already collected (within last 7 days)
        c.execute("SELECT keyword FROM keyword_trends WHERE updated_at > NOW() - INTERVAL '7 days'")
        existing = set(row[0].lower() for row in c.fetchall())

        # Find keywords needing trends data (prioritize A-tier and interested)
        try:
            c.execute("SELECT keyword, label FROM keyword_labels WHERE label IN ('interested', 'researching')")
            priority_keywords = set(row[0] for row in c.fetchall())
        except Exception:
            priority_keywords = set()

        keywords_needing_data = []
        for kw in KEYWORDS:
            if kw['keyword'].lower() not in existing:
                if kw['keyword'] in priority_keywords or 'A -' in kw.get('tier', ''):
                    keywords_needing_data.insert(0, kw['keyword'])
                else:
                    keywords_needing_data.append(kw['keyword'])

        results['total'] = len(keywords_needing_data)
        results['remaining'] = len(keywords_needing_data)
        trends_collection_status['last_results'] = results
        print(f"[TRENDS] Processing ALL {len(keywords_needing_data)} keywords needing trends data")

        consecutive_failures = 0
        for i, keyword in enumerate(keywords_needing_data):
            # Check if stop was requested
            if trends_collection_status.get('stop_requested'):
                print(f"[TRENDS] Stop requested after {results['processed']} keywords")
                break

            try:
                trend_data = get_serpapi_google_trends(keyword)

                if trend_data.get('success'):
                    c.execute('''
                        INSERT INTO keyword_trends (keyword, trend, trend_change_pct, current_interest, data_points,
                            peak_months, low_months, seasonality_score, publish_window, monthly_averages, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT(keyword) DO UPDATE SET
                            trend = EXCLUDED.trend,
                            trend_change_pct = EXCLUDED.trend_change_pct,
                            current_interest = EXCLUDED.current_interest,
                            data_points = EXCLUDED.data_points,
                            peak_months = EXCLUDED.peak_months,
                            low_months = EXCLUDED.low_months,
                            seasonality_score = EXCLUDED.seasonality_score,
                            publish_window = EXCLUDED.publish_window,
                            monthly_averages = EXCLUDED.monthly_averages,
                            updated_at = CURRENT_TIMESTAMP
                    ''', (
                        keyword,
                        trend_data.get('trend', 'unknown'),
                        trend_data.get('trend_change_pct', 0),
                        trend_data.get('current_interest', 0),
                        trend_data.get('data_points', 0),
                        trend_data.get('peak_months'),
                        trend_data.get('low_months'),
                        trend_data.get('seasonality_score', 0),
                        trend_data.get('publish_window'),
                        _json.dumps(trend_data.get('monthly_averages')) if trend_data.get('monthly_averages') else None
                    ))
                    conn.commit()
                    # Update in-memory cache
                    update_trends_cache(keyword, trend_data)
                    results['success'] += 1
                    consecutive_failures = 0
                else:
                    error_msg = trend_data.get('error', '')
                    results['failed'] += 1
                    consecutive_failures += 1
                    # If rate limited or API error, back off
                    if '429' in str(error_msg) or 'rate' in str(error_msg).lower():
                        print(f"[TRENDS] Rate limited, backing off 30s...")
                        _time.sleep(30)
                        consecutive_failures = 0  # Reset after backoff

                results['processed'] += 1
                results['remaining'] = results['total'] - results['processed']

                # Update status for real-time tracking
                if results['processed'] % 10 == 0:
                    trends_collection_status['last_results'] = results.copy()
                    print(f"[TRENDS] Progress: {results['processed']}/{results['total']} ({results['success']} ok, {results['failed']} failed, {results['remaining']} left)")

                # Stop if too many consecutive failures (API key exhausted, etc.)
                if consecutive_failures >= 10:
                    print(f"[TRENDS] Stopping: {consecutive_failures} consecutive failures")
                    results['stopped_reason'] = f'{consecutive_failures} consecutive API failures'
                    break

                # Rate limit: 1 second between requests, 3 second pause every batch
                _time.sleep(1)
                if (i + 1) % batch_size == 0:
                    _time.sleep(3)

            except Exception as e:
                print(f"[TRENDS] Error processing {keyword}: {e}")
                results['failed'] += 1
                results['processed'] += 1
                results['remaining'] = results['total'] - results['processed']
                consecutive_failures += 1
                # Reconnect DB if connection lost
                if 'connection' in str(e).lower() or 'closed' in str(e).lower():
                    try:
                        conn = get_db()
                        c = conn.cursor()
                        print("[TRENDS] DB reconnected")
                    except Exception:
                        print("[TRENDS] DB reconnect failed, stopping")
                        break

        try:
            release_db(conn)
        except Exception:
            pass
        print(f"[TRENDS] Complete: {results}")

    except Exception as e:
        print(f"[TRENDS] Error: {e}")
        results['error'] = str(e)

    finally:
        trends_collection_status['running'] = False
        trends_collection_status['stop_requested'] = False
        trends_collection_status['last_run'] = datetime.now().isoformat()
        trends_collection_status['last_results'] = results

@app.route('/api/cron/collect-trends')
def cron_collect_trends():
    """
    Collect Google Trends data for keywords missing it.
    Call: GET /api/cron/collect-trends?secret=YOUR_CRON_SECRET&batch=25
    Runs in background and returns immediately.
    """
    import threading

    # Verify cron secret or login
    cron_secret = os.environ.get('CRON_SECRET', '')
    provided_secret = request.args.get('secret', '')
    skip_auth = not os.environ.get('GOOGLE_CLIENT_ID')
    is_logged_in = skip_auth or 'user' in session

    if not is_logged_in and cron_secret and provided_secret != cron_secret:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    if trends_collection_status['running']:
        return jsonify({
            'success': False,
            'error': 'Trends collection already in progress',
            'status': trends_collection_status
        })

    batch_size = min(int(request.args.get('batch', 25)), 50)

    thread = threading.Thread(target=collect_trends_data_background, args=(batch_size,))
    thread.daemon = True
    thread.start()

    return jsonify({
        'success': True,
        'message': f'Trends collection started — processing ALL remaining keywords continuously',
        'check_status': '/api/cron/trends-status'
    })

@app.route('/api/cron/stop-trends')
@login_required
def stop_trends_collection():
    """Stop the running trends collection gracefully"""
    if trends_collection_status['running']:
        trends_collection_status['stop_requested'] = True
        return jsonify({'success': True, 'message': 'Stop requested — collection will finish current keyword and stop'})
    return jsonify({'success': False, 'message': 'No collection running'})

@app.route('/api/cron/trends-status')
def cron_trends_status():
    """Check status of Google Trends data collection"""
    try:
        conn = get_db()
        c = conn.cursor()

        c.execute('SELECT COUNT(*) FROM keyword_trends')
        collected_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM keyword_trends WHERE updated_at > NOW() - INTERVAL '7 days'")
        fresh_count = c.fetchone()[0]

        release_db(conn)

        return jsonify({
            'success': True,
            'total_keywords': len(KEYWORDS),
            'trends_collected_total': collected_count,
            'trends_fresh_7d': fresh_count,
            'still_needed': max(0, len(KEYWORDS) - fresh_count),
            'job_running': trends_collection_status['running'],
            'last_run': trends_collection_status['last_run'],
            'last_results': trends_collection_status['last_results']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# DOMINATION AUDIT JOB
# ============================================
def run_domination_audit_job():
    """Background job to run domination score audit using BigQuery data.
    Primary keyword source: priority_keywords table (active keywords).
    Fallback: keyword_tracking.json, then previous audit data, then keywords_master."""
    import threading

    def _audit():
        try:
            keywords_to_check = []
            keyword_meta = {}  # keyword -> {silo, group, is_secondary, revenue}
            keyword_source = 'unknown'

            # Source 1 (preferred): priority_keywords table
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute('SELECT keyword, niche, priority_score, search_volume FROM priority_keywords WHERE is_active = TRUE ORDER BY priority_score DESC')
                priority_rows = c.fetchall()
                release_db(conn)

                if priority_rows:
                    # Also load revenue from keyword_tracking.json for enrichment
                    tracking_flat = get_tracking_keywords_flat()
                    tracking_revenue = {e['keyword'].lower(): e.get('revenue', 0) for e in tracking_flat}
                    tracking_meta = {e['keyword'].lower(): e for e in tracking_flat}

                    for row in priority_rows:
                        kw = row[0]
                        kw_lower = kw.lower()
                        keywords_to_check.append(kw)
                        # Merge: use tracking meta if available, else build from DB
                        if kw_lower in tracking_meta:
                            keyword_meta[kw] = tracking_meta[kw_lower]
                        else:
                            keyword_meta[kw] = {
                                'keyword': kw,
                                'silo': row[1] or '',
                                'group': '',
                                'is_secondary': False,
                                'revenue': tracking_revenue.get(kw_lower, 0),
                            }
                    keyword_source = 'priority_keywords'
                    print(f"[AUDIT-BQ] Loaded {len(keywords_to_check)} keywords from priority_keywords table")
            except Exception as e:
                print(f"[AUDIT-BQ] Could not read priority_keywords: {e}")

            # Source 2 (fallback): keyword_tracking.json
            if not keywords_to_check:
                tracking_keywords = get_tracking_keywords_flat()
                if tracking_keywords:
                    for entry in tracking_keywords:
                        kw = entry['keyword']
                        keywords_to_check.append(kw)
                        keyword_meta[kw] = entry
                    keyword_source = 'keyword_tracking'
                    print(f"[AUDIT-BQ] Loaded {len(keywords_to_check)} keywords from keyword_tracking.json")

            # Source 3 (fallback): Previous audit data
            if not keywords_to_check:
                current_data = None
                data_path = DOMINATION_DATA_PATH if os.path.exists(DOMINATION_DATA_PATH) else BUNDLED_RANKING_PATH

                if os.path.exists(data_path):
                    with open(data_path, 'r') as f:
                        current_data = json.load(f)

                if not current_data:
                    try:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute('SELECT audit_json FROM domination_audits ORDER BY created_at DESC LIMIT 1')
                        row = c.fetchone()
                        release_db(conn)
                        if row and row[0]:
                            current_data = json.loads(row[0])
                    except Exception:
                        pass

                if current_data:
                    for item in current_data.get('ranking', []):
                        kw = item['keyword']
                        keywords_to_check.append(kw)
                        keyword_meta[kw] = {'revenue': item.get('revenue', 0), 'is_secondary': False}
                    for item in current_data.get('not_ranking', []):
                        kw = item['keyword']
                        keywords_to_check.append(kw)
                        keyword_meta[kw] = {'revenue': item.get('revenue', 0), 'is_secondary': False}
                    keyword_source = 'previous_audit'

                # Source 4: keywords_master fallback
                if not keywords_to_check:
                    try:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute('''
                            SELECT keyword, revenue_potential FROM keywords_master
                            WHERE intent_type IN ('review', 'comparison', 'best_of', 'deal')
                            AND revenue_potential > 0
                            ORDER BY revenue_potential DESC LIMIT 50
                        ''')
                        for row in c.fetchall():
                            keywords_to_check.append(row[0])
                            keyword_meta[row[0]] = {'revenue': row[1] or 0, 'is_secondary': False}
                        release_db(conn)
                        keyword_source = 'keywords_master'
                    except Exception:
                        pass

            if not keywords_to_check:
                print("[AUDIT-BQ] Skipped: No keywords to audit from any source")
                return

            print(f"[AUDIT-BQ] Starting BigQuery audit for {len(keywords_to_check)} keywords...")

            # Single batch query to BigQuery (replaces N individual SerpAPI calls)
            bq_results = fetch_domination_from_bigquery(keywords_to_check)

            if not bq_results:
                print("[AUDIT-BQ] WARNING: No results from BigQuery")
                return

            all_results = []
            ranking = []
            not_ranking = []
            scrape_date = None

            for keyword in keywords_to_check:
                meta = keyword_meta.get(keyword, {})
                bq_data = bq_results.get(keyword.lower())

                if bq_data:
                    if not scrape_date:
                        scrape_date = bq_data.get('scrape_date')

                    result = {
                        'keyword': keyword,
                        'top_10': bq_data['top_10'],
                        'silo': meta.get('silo', ''),
                        'group': meta.get('group', ''),
                        'is_secondary': meta.get('is_secondary', False),
                        'search_volume': bq_data.get('search_volume', 0),
                    }
                    all_results.append(result)

                    is_ranking = bq_data['domination_score'] > 0
                    kw_data = {
                        'keyword': keyword,
                        'revenue': meta.get('revenue', 0),
                        'silo': meta.get('silo', ''),
                        'group': meta.get('group', ''),
                        'is_secondary': meta.get('is_secondary', False),
                    }
                    if is_ranking:
                        ranking.append(kw_data)
                    else:
                        not_ranking.append(kw_data)
                else:
                    # Keyword not found in BigQuery SERP data
                    result = {
                        'keyword': keyword,
                        'top_10': [],
                        'silo': meta.get('silo', ''),
                        'group': meta.get('group', ''),
                        'is_secondary': meta.get('is_secondary', False),
                    }
                    all_results.append(result)
                    not_ranking.append({
                        'keyword': keyword,
                        'revenue': meta.get('revenue', 0),
                        'silo': meta.get('silo', ''),
                        'group': meta.get('group', ''),
                        'is_secondary': meta.get('is_secondary', False),
                    })

            audit_data = {
                'timestamp': datetime.now().isoformat(),
                'source': 'bigquery',
                'keyword_source': keyword_source,
                'scrape_date': scrape_date,
                'revenue_period': 'Current',
                'ranking': ranking,
                'not_ranking': not_ranking,
                'all_results': all_results,
            }

            os.makedirs(os.path.dirname(DOMINATION_DATA_PATH), exist_ok=True)
            with open(DOMINATION_DATA_PATH, 'w') as f:
                json.dump(audit_data, f, indent=2)

            store_ranking_snapshot(audit_data)
            print(f"[AUDIT-BQ] Completed: {len(ranking)} ranking, {len(not_ranking)} not ranking "
                  f"(total: {len(all_results)}, scrape_date: {scrape_date})")

        except Exception as e:
            print(f"[AUDIT-BQ] Error: {str(e)}")
            import traceback
            traceback.print_exc()

    thread = threading.Thread(target=_audit, daemon=True)
    thread.start()


# ============================================
# DAILY SCHEDULER + STARTUP COLLECTION
# ============================================

def _make_naive(dt):
    """Strip timezone info from a datetime for safe comparison with datetime.now()."""
    if dt and hasattr(dt, 'tzinfo') and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def check_data_staleness():
    """Check if domination and trends data is stale and needs refreshing."""
    staleness = {'domination_stale': True, 'trends_stale': True, 'domination_last': None, 'trends_last': None, 'bq_last_scrape': None}

    # Check BigQuery freshness first (primary source)
    try:
        client = get_bq_client()
        if client:
            bq_query = f"""
            SELECT MAX(Scrape_date) as latest
            FROM {BQ_SERP_TABLE}
            WHERE Scrape_date = BQ_asia_scrape_date
            """
            bq_result = list(client.query(bq_query).result())
            if bq_result and bq_result[0].latest:
                from datetime import date
                latest_date = bq_result[0].latest
                staleness['bq_last_scrape'] = str(latest_date)
                staleness['domination_last'] = str(latest_date)
                days_old = (date.today() - latest_date).days
                staleness['domination_stale'] = days_old > 2  # BQ scraper runs daily, allow 2-day buffer
    except Exception as bq_err:
        print(f"[STALENESS] BigQuery check error: {bq_err}")

    # Fallback: Supabase ranking_history
    if staleness['domination_last'] is None:
        try:
            conn = get_db()
            c = conn.cursor()

            last_dom_dt = None
            c.execute('SELECT MAX(snapshot_date) FROM ranking_history')
            row = c.fetchone()
            if row and row[0]:
                staleness['domination_last'] = str(row[0])
                try:
                    val = row[0]
                    if isinstance(val, datetime):
                        last_dom_dt = _make_naive(val)
                    elif isinstance(val, str):
                        last_dom_dt = datetime.fromisoformat(val.replace('Z', '+00:00')).replace(tzinfo=None) if 'T' in val else datetime.strptime(val, '%Y-%m-%d %H:%M:%S')
                    else:
                        last_dom_dt = datetime.strptime(str(val), '%Y-%m-%d %H:%M:%S')
                except Exception as parse_err:
                    print(f"[STALENESS] Date parse error (ranking_history): {parse_err}")

            if not last_dom_dt:
                try:
                    c.execute('SELECT MAX(created_at) FROM domination_audits')
                    row2 = c.fetchone()
                    if row2 and row2[0]:
                        val2 = row2[0]
                        if isinstance(val2, datetime):
                            last_dom_dt = _make_naive(val2)
                        elif isinstance(val2, str):
                            last_dom_dt = datetime.fromisoformat(val2.replace('Z', '+00:00')).replace(tzinfo=None) if 'T' in val2 else datetime.strptime(val2, '%Y-%m-%d %H:%M:%S')
                        staleness['domination_last'] = str(val2)
                except Exception:
                    pass

            if last_dom_dt:
                staleness['domination_stale'] = (datetime.now() - last_dom_dt).total_seconds() > 86400

            release_db(conn)
        except Exception as e:
            print(f"[STALENESS] Supabase staleness check error: {e}")

    # Fallback: check local domination_data.json
    if staleness['domination_last'] is None and os.path.exists(DOMINATION_DATA_PATH):
        try:
            with open(DOMINATION_DATA_PATH, 'r') as f:
                local_data = json.load(f)
            ts = local_data.get('timestamp')
            if ts:
                staleness['domination_last'] = ts
                local_dt = datetime.fromisoformat(ts)
                staleness['domination_stale'] = (datetime.now() - local_dt).total_seconds() > 86400
        except Exception as file_err:
            print(f"[STALENESS] Error reading local domination file: {file_err}")

    # Check trends staleness (unchanged)
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM keyword_trends WHERE updated_at > NOW() - INTERVAL '7 days'")
        fresh_trends = c.fetchone()[0]
        staleness['trends_fresh'] = fresh_trends
        staleness['trends_stale'] = fresh_trends < len(KEYWORDS) * 0.1
        release_db(conn)
    except Exception as e:
        print(f"[STALENESS] Trends staleness check error: {e}")

    return staleness


def run_startup_collection():
    """On app startup, check if data is stale and trigger background collection."""
    import time as _time
    _time.sleep(10)  # Wait for app to fully initialize

    print("[STARTUP] Checking data staleness...")
    staleness = check_data_staleness()
    print(f"[STARTUP] Domination stale: {staleness['domination_stale']} (last: {staleness['domination_last']})")
    print(f"[STARTUP] Trends stale: {staleness['trends_stale']} (fresh: {staleness.get('trends_fresh', 0)})")

    if staleness['domination_stale']:
        print("[STARTUP] Domination data is stale, triggering audit...")
        run_domination_audit_job()

    # Trends collection is now manual (Fetch button per keyword) — no auto-collection
    print(f"[STARTUP] Trends: {staleness.get('trends_fresh', 0)} keywords have data (manual fetch only)")


def run_daily_collection_job():
    """Daily job: domination audit only. Trends are manual (Fetch button)."""
    print("[DAILY] Running domination audit...")
    run_domination_audit_job()


# Start scheduler - run every 6 hours to survive Railway restarts
scheduler = BackgroundScheduler()
scheduler.add_job(
    run_daily_collection_job,
    'interval',
    hours=6,
    id='periodic_collection',
    replace_existing=True
)
scheduler.start()
print("[SCHEDULER] Collection job scheduled every 6 hours")

# Run startup collection in background thread
import threading
startup_thread = threading.Thread(target=run_startup_collection, daemon=True)
startup_thread.start()
print("[STARTUP] Startup staleness check queued")


# ============================================
# UNIFIED CRON ENDPOINT (for external triggers)
# ============================================
@app.route('/api/cron/run-all')
def cron_run_all():
    """
    Single endpoint for external cron services to trigger all data collection.
    Call daily: GET /api/cron/run-all?secret=YOUR_CRON_SECRET
    Triggers domination audit + trends collection in background.
    """
    import threading

    cron_secret = os.environ.get('CRON_SECRET', '')
    provided_secret = request.args.get('secret', '')
    skip_auth = not os.environ.get('GOOGLE_CLIENT_ID')
    is_logged_in = skip_auth or 'user' in session

    if not is_logged_in and cron_secret and provided_secret != cron_secret:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    thread = threading.Thread(target=run_daily_collection_job, daemon=True)
    thread.start()

    return jsonify({
        'success': True,
        'message': 'All collection jobs started in background',
        'jobs': ['domination_audit', 'trends_collection'],
        'check_status': {
            'trends': '/api/cron/trends-status',
            'staleness': '/api/data/staleness'
        }
    })


@app.route('/api/data/staleness')
@login_required
def get_data_staleness():
    """Returns freshness info for all data sources."""
    staleness = check_data_staleness()
    return jsonify({
        'success': True,
        **staleness,
        'domination_audit_file_exists': os.path.exists(DOMINATION_DATA_PATH),
        'bundled_data_exists': os.path.exists(BUNDLED_RANKING_PATH),
        'keywords_in_memory': len(KEYWORDS),
        'db_last_error': _last_db_error
    })

# ============================================
# $3K OPPORTUNITY FINDER
# ============================================

def _parse_competition(val):
    """Convert competition value to float 0-1. Handles numeric, string ('Low','Medium','High'), or empty."""
    if not val:
        return 0
    if isinstance(val, (int, float)):
        return float(val)
    val_str = str(val).strip().lower()
    mapping = {'low': 0.15, 'medium': 0.5, 'high': 0.85}
    if val_str in mapping:
        return mapping[val_str]
    try:
        return float(val_str)
    except (ValueError, TypeError):
        return 0

@app.route('/api/trending-gaps')
@login_required
def trending_gaps():
    """Find trending topics from Google Trends that aren't in the keyword library.
    Uses silo primary keywords as seeds, fetches rising related queries, filters out existing keywords."""
    silo_filter = request.args.get('silo', 'all')

    # Load silo seeds from keyword_tracking.json
    tracking_path = os.path.join(os.path.dirname(__file__), 'data', 'keyword_tracking.json')
    try:
        with open(tracking_path, 'r') as f:
            config = json.load(f)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Could not load tracking config: {e}'}), 500

    # Build set of existing keywords for fast lookup
    existing_kws = set(k.get('keyword', '').lower().strip() for k in KEYWORDS)

    # Collect seed keywords from silos
    seeds = []
    for silo in config.get('silos', []):
        silo_id = silo.get('id', '')
        if silo_filter != 'all' and silo_id != silo_filter:
            continue
        for group in silo.get('groups', []):
            for kw_entry in group.get('keywords', []):
                seeds.append({'keyword': kw_entry['keyword'], 'silo': silo_id})

    # Query Google Trends rising queries for each seed
    all_trending = []
    seen = set()
    errors = []

    for seed in seeds:
        try:
            result = get_serpapi_related_queries(seed['keyword'])
            if result.get('success'):
                for rq in result.get('related', []):
                    kw = rq.get('keyword', '').strip()
                    kw_lower = kw.lower()
                    if not kw or kw_lower in seen:
                        continue
                    seen.add(kw_lower)
                    in_library = kw_lower in existing_kws
                    all_trending.append({
                        'keyword': kw,
                        'trend_type': rq.get('trend_type', 'unknown'),
                        'trend_value': rq.get('value', 0),
                        'seed_keyword': seed['keyword'],
                        'silo': seed['silo'],
                        'in_library': in_library
                    })
            else:
                errors.append(f"{seed['keyword']}: {result.get('error', 'unknown error')}")
        except Exception as e:
            errors.append(f"{seed['keyword']}: {str(e)}")

    # Separate into gaps (not in library) and covered (already in library)
    gaps = [t for t in all_trending if not t['in_library']]
    covered = [t for t in all_trending if t['in_library']]

    # Sort gaps: rising first (breakout/high value), then by trend_value descending
    def sort_key(item):
        is_rising = 1 if item['trend_type'] == 'rising' else 0
        val = item.get('trend_value', 0)
        if isinstance(val, str):
            val = 99999 if val.lower() == 'breakout' else 0
        return (is_rising, val)

    gaps.sort(key=sort_key, reverse=True)

    return jsonify({
        'success': True,
        'gaps': gaps,
        'covered': covered,
        'total_trending': len(all_trending),
        'gap_count': len(gaps),
        'covered_count': len(covered),
        'seeds_queried': len(seeds),
        'silos': [s['id'] for s in config.get('silos', [])],
        'errors': errors
    })


@app.route('/api/opportunity-finder')
@login_required
@cache_response('opportunity_finder', ttl_seconds=600)  # 10 min cache
def opportunity_finder():
    """
    Analyzes every keyword for $3K/mo revenue feasibility.
    Returns keywords ranked by how achievable $3K/mo is.
    """
    TARGET = 3000  # $3K/mo target

    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'

    labels = {}
    yt_db = {}
    trends = {}
    votes = {}

    try:
        conn = get_db()
        c = conn.cursor()

        # Get labels (with attribution)
        c.execute('SELECT keyword, label, is_favorite, notes, label_updated_by, favorite_updated_by, notes_updated_by FROM keyword_labels')
        for row in c.fetchall():
            labels[row[0]] = {
                'label': row[1], 'favorite': bool(row[2]), 'notes': row[3],
                'labelBy': row[4] or '', 'favoriteBy': row[5] or '', 'notesBy': row[6] or ''
            }

        # Get YT data
        c.execute('SELECT keyword, yt_avg_views, yt_view_pattern FROM keyword_yt_data')
        yt_db = {row[0].lower(): {'avg_views': row[1], 'view_pattern': row[2]} for row in c.fetchall()}

        # Get trends
        c.execute('SELECT keyword, trend, trend_change_pct, current_interest, peak_months, seasonality_score, publish_window FROM keyword_trends')
        trends = {row[0].lower(): {'trend': row[1], 'change': row[2], 'interest': row[3], 'peakMonths': row[4], 'seasonalityScore': row[5] or 0, 'publishWindow': row[6]} for row in c.fetchall()}

        # Get vote scores
        c.execute('''
            SELECT keyword,
                   COALESCE(SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END), 0) -
                   COALESCE(SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END), 0) as score
            FROM keyword_votes GROUP BY keyword
        ''')
        votes = {row[0]: row[1] for row in c.fetchall()}

        release_db(conn)
    except Exception as e:
        print(f"[OPPORTUNITY] DB unavailable, using in-memory data only: {e}")

    # Get domination data if available
    domination = {}
    try:
        dom_path = DOMINATION_DATA_PATH if os.path.exists(DOMINATION_DATA_PATH) else BUNDLED_RANKING_PATH
        if os.path.exists(dom_path):
            with open(dom_path, 'r') as f:
                dom_data = json.load(f)
            for item in dom_data.get('ranking', []):
                kw = item.get('keyword', '').lower()
                positions = item.get('positions', [])
                score = 0
                weights = {1: 50, 2: 25, 3: 15, 4: 5, 5: 5}
                for pos in positions:
                    p = pos.get('position', 0)
                    if p in weights:
                        score += weights[p]
                domination[kw] = {
                    'score': score,
                    'positions_owned': len(positions),
                    'revenue': item.get('revenue', 0)
                }
    except Exception as e:
        print(f"[OPPORTUNITY] Error loading domination data: {e}")

    opportunities = []
    for k in KEYWORDS:
        keyword = k['keyword']
        keyword_lower = keyword.lower()
        volume = k.get('volume', 0) or 0
        niche = k.get('niche', 'general')

        # Get YT data (prefer DB, fallback to CSV)
        yt_data = yt_db.get(keyword_lower, {})
        pattern = yt_data.get('view_pattern') or k.get('ytPattern', 'no_data') or 'no_data'
        avg_views = yt_data.get('avg_views') or k.get('ytViews', 0) or 0

        # Keyword type classification
        keyword_type = classify_keyword_type(keyword)

        # EPV
        epv_by_type = {
            'deal': 1.18, 'comparison': 0.53, 'review': 0.31,
            'best_of': 0.16, 'informational': 0.31, 'other': 0.17
        }
        base_epv = epv_by_type.get(keyword_type, 0.17)

        # Niche multiplier
        niche_multipliers = {
            'vpn': 1.5, 'identity_theft': 1.4, 'data_broker_removal': 1.3,
            'antivirus': 1.2, 'web_hosting': 1.3, 'email_marketing': 1.2,
            'parental_control': 1.1, 'home_security': 1.0, 'pet_tech': 1.0
        }
        niche_mult = niche_multipliers.get(niche, 1.0)
        adjusted_epv = base_epv * niche_mult

        # Capture rate
        capture_rates = {
            'distributed': 0.15, 'top_heavy': 0.08,
            'winner_take_all': 0.03, 'no_data': 0.10
        }
        capture_rate = capture_rates.get(pattern, 0.10)

        # Willingness
        willingness = estimate_willingness_to_spend(keyword, keyword_type, niche)

        # Current estimated revenue
        monthly_traffic = volume * capture_rate
        est_revenue = monthly_traffic * adjusted_epv * willingness

        # Revenue at 75th percentile EPV (upside case)
        epv_75th = {
            'deal': 4.69, 'comparison': 1.27, 'review': 0.72,
            'best_of': 0.42, 'informational': 0.50, 'other': 0.30
        }
        upside_epv = epv_75th.get(keyword_type, 0.30) * niche_mult
        upside_revenue = monthly_traffic * upside_epv * willingness

        # Volume needed to hit $3K at current EPV & capture
        if adjusted_epv * capture_rate * willingness > 0:
            volume_needed = TARGET / (adjusted_epv * capture_rate * willingness)
        else:
            volume_needed = float('inf')

        # Gap analysis
        revenue_gap = max(0, TARGET - est_revenue)
        gap_percentage = (est_revenue / TARGET * 100) if TARGET > 0 else 0

        # Trend data
        trend_data = trends.get(keyword_lower, {})
        trend_direction = trend_data.get('trend', 'unknown')
        trend_change = trend_data.get('change', 0)

        # Domination data
        dom = domination.get(keyword_lower, {})
        dom_score = dom.get('score', 0)
        dom_actual_revenue = dom.get('revenue', 0)

        # ============================================
        # FEASIBILITY SCORE (0-100)
        # ============================================
        feasibility = 0

        # 1. Revenue proximity (0-35 points)
        # How close is current estimate to $3K?
        if est_revenue >= TARGET:
            feasibility += 35  # Already there!
        elif est_revenue >= TARGET * 0.5:
            feasibility += 25 + (est_revenue - TARGET * 0.5) / (TARGET * 0.5) * 10
        elif est_revenue >= TARGET * 0.2:
            feasibility += 15 + (est_revenue - TARGET * 0.2) / (TARGET * 0.3) * 10
        elif est_revenue >= TARGET * 0.05:
            feasibility += 5 + (est_revenue - TARGET * 0.05) / (TARGET * 0.15) * 10
        else:
            feasibility += min(5, est_revenue / (TARGET * 0.05) * 5)

        # 2. Upside potential (0-20 points)
        # Can this keyword reach $3K at 75th percentile EPV?
        if upside_revenue >= TARGET:
            feasibility += 20
        elif upside_revenue >= TARGET * 0.5:
            feasibility += 10 + (upside_revenue / TARGET) * 10
        else:
            feasibility += (upside_revenue / TARGET) * 10

        # 3. Volume headroom (0-15 points)
        # Is there enough search volume?
        if volume >= volume_needed:
            feasibility += 15
        elif volume >= volume_needed * 0.5:
            feasibility += 8 + (volume / volume_needed) * 7
        elif volume > 0:
            feasibility += (volume / volume_needed) * 8
        # else: 0 points (no volume data)

        # 4. Competition favorability (0-15 points)
        pattern_scores = {
            'distributed': 15, 'top_heavy': 8,
            'winner_take_all': 3, 'no_data': 6
        }
        feasibility += pattern_scores.get(pattern, 6)

        # 5. Trend momentum (0-10 points)
        if trend_direction == 'rising':
            feasibility += 10
        elif trend_direction == 'stable':
            feasibility += 5
        elif trend_direction == 'declining':
            feasibility += 0
        else:
            feasibility += 3  # Unknown, slight credit

        # 5b. Seasonal timing bonus (0-5 points) — boost keywords approaching their peak season
        publish_window = trend_data.get('publishWindow')
        if publish_window:
            month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            current_month = month_names[datetime.now().month - 1]
            peak_months_str = trend_data.get('peakMonths', '')
            window_months = publish_window.split('-') if publish_window else []
            if current_month in window_months:
                feasibility += 5  # Publish NOW — approaching peak
                levers.append(f"Publish now! Peak season ({peak_months_str}) approaching")
            elif peak_months_str and current_month in peak_months_str.split(','):
                feasibility += 3  # Currently in peak season
                levers.append(f"Currently in peak season ({peak_months_str})")

        # 6. Keyword type bonus (0-5 points)
        type_bonus = {'deal': 5, 'comparison': 4, 'review': 3, 'best_of': 2, 'informational': 0, 'other': 1}
        feasibility += type_bonus.get(keyword_type, 1)

        feasibility = min(100, max(0, round(feasibility, 1)))

        # Determine the primary lever to pull
        levers = []
        if volume < volume_needed and volume > 0:
            levers.append(f"Need {int(volume_needed):,} monthly searches (have {volume:,})")
        if pattern == 'winner_take_all':
            levers.append("High competition - target long-tail variants")
        elif pattern == 'top_heavy':
            levers.append("Moderate competition - can outrank with quality")
        if willingness < 0.5:
            levers.append(f"Low buyer intent ({willingness:.0%}) - focus on purchase-intent angles")
        if trend_direction == 'declining':
            levers.append("Declining trend - consider timing risk")
        if dom_score > 0 and dom_score < 50:
            levers.append(f"Only {dom_score}% domination - room to grow rankings")
        if not levers and est_revenue < TARGET:
            levers.append("Increase content volume and ranking positions")

        label_data = labels.get(keyword, {})

        opportunities.append({
            'keyword': keyword,
            'niche': niche,
            'keywordType': keyword_type,
            'volume': volume,
            'pattern': pattern,
            'avgViews': avg_views,
            'epv': round(adjusted_epv, 2),
            'captureRate': round(capture_rate * 100, 1),
            'willingness': willingness,
            'estRevenue': round(est_revenue, 0),
            'upsideRevenue': round(upside_revenue, 0),
            'revenueGap': round(revenue_gap, 0),
            'gapPercentage': round(gap_percentage, 1),
            'volumeNeeded': round(volume_needed, 0) if volume_needed != float('inf') else None,
            'feasibility': feasibility,
            'trend': trend_direction,
            'trendChange': trend_change,
            'peakMonths': trend_data.get('peakMonths'),
            'seasonalityScore': trend_data.get('seasonalityScore', 0),
            'publishWindow': trend_data.get('publishWindow'),
            'domScore': dom_score,
            'domRevenue': dom_actual_revenue,
            'voteScore': votes.get(keyword, 0),
            'label': label_data.get('label', 'none'),
            'favorite': label_data.get('favorite', False),
            'tier': k.get('tier', 'D - Nurture'),
            'levers': levers,
            'nicheMult': niche_mult,
            'competition': _parse_competition(k.get('competition', 0))
        })

    # Sort by feasibility desc
    opportunities.sort(key=lambda x: x['feasibility'], reverse=True)

    # Add rank
    for i, opp in enumerate(opportunities):
        opp['rank'] = i + 1

    # Summary stats
    above_3k = sum(1 for o in opportunities if o['estRevenue'] >= TARGET)
    above_1k = sum(1 for o in opportunities if o['estRevenue'] >= 1000)
    above_500 = sum(1 for o in opportunities if o['estRevenue'] >= 500)
    top_10_revenue = sum(o['estRevenue'] for o in opportunities[:10])

    # Niche clusters: group top opportunities by niche to show cluster strategy
    niche_clusters = {}
    for opp in opportunities:
        n = opp['niche']
        if n not in niche_clusters:
            niche_clusters[n] = {'niche': n, 'count': 0, 'totalRevenue': 0,
                                 'totalUpside': 0, 'avgFeasibility': 0,
                                 'bestKeyword': '', 'bestRevenue': 0}
        niche_clusters[n]['count'] += 1
        niche_clusters[n]['totalRevenue'] += opp['estRevenue']
        niche_clusters[n]['totalUpside'] += opp['upsideRevenue']
        niche_clusters[n]['avgFeasibility'] += opp['feasibility']
        if opp['estRevenue'] > niche_clusters[n]['bestRevenue']:
            niche_clusters[n]['bestRevenue'] = opp['estRevenue']
            niche_clusters[n]['bestKeyword'] = opp['keyword']

    clusters = []
    for c_data in niche_clusters.values():
        if c_data['count'] > 0:
            c_data['avgFeasibility'] = round(c_data['avgFeasibility'] / c_data['count'], 1)
            c_data['totalRevenue'] = round(c_data['totalRevenue'], 0)
            c_data['totalUpside'] = round(c_data['totalUpside'], 0)
            c_data['revenuePerKeyword'] = round(c_data['totalRevenue'] / c_data['count'], 0)
            clusters.append(c_data)

    clusters.sort(key=lambda x: x['totalRevenue'], reverse=True)

    return jsonify({
        'success': True,
        'target': TARGET,
        'opportunities': opportunities,
        'clusters': clusters,
        'summary': {
            'total_keywords': len(opportunities),
            'above_target': above_3k,
            'above_1k': above_1k,
            'above_500': above_500,
            'top_10_combined_revenue': round(top_10_revenue, 0),
            'top_10_feasibility_avg': round(sum(o['feasibility'] for o in opportunities[:10]) / min(10, len(opportunities)), 1)
        }
    })


# ============================================
# KEYWORD UNIVERSE MAPPER
# ============================================

# Comprehensive brand lists per niche
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

# Intent modifiers for brand keywords
BRAND_INTENTS = {
    'review': ['{brand} review', '{brand} review 2026', '{brand} reviews',
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

# "Best X for Y" use cases per niche
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
                      'alexa', 'google home', 'homekit'],
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
                      'auto loan', 'collections', 'bankrupty',
                      'student loans', 'medical debt']
}

# Problem keywords per niche (beyond brands)
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
        'web hosting uptime explained', 'cPanel vs plesk'
    ],
    'email_marketing': [
        'how to build email list', 'email marketing for beginners',
        'how to improve open rates', 'email deliverability tips',
        'email automation workflows', 'welcome email sequence',
        'email list segmentation', 'email marketing vs social media',
        'gdpr email marketing', 'email marketing roi'
    ]
}


@app.route('/api/keyword-universe')
@login_required
@cache_response('keyword_universe', ttl_seconds=600)  # 10 min cache
def keyword_universe():
    """
    Maps the total keyword universe per niche, showing coverage gaps.
    Generates all possible keyword combinations and cross-references
    against the existing library.
    """
    # Build set of existing keywords (lowercased)
    existing = set(k['keyword'].lower().strip() for k in KEYWORDS)

    niches_analysis = []

    for niche, brands in UNIVERSE_BRANDS.items():
        universe = set()
        categories = {}

        # 1. Brand vs Brand comparisons
        comparison_kws = set()
        for i, brand_a in enumerate(brands):
            for brand_b in brands[i+1:]:
                comparison_kws.add(f"{brand_a} vs {brand_b}")
                comparison_kws.add(f"{brand_b} vs {brand_a}")
                comparison_kws.add(f"{brand_a} or {brand_b}")
                comparison_kws.add(f"{brand_b} or {brand_a}")
        universe.update(comparison_kws)
        categories['comparisons'] = {
            'total': len(comparison_kws),
            'existing': len(comparison_kws & existing),
            'gap': len(comparison_kws - existing),
            'coverage_pct': round(len(comparison_kws & existing) / max(1, len(comparison_kws)) * 100, 1)
        }

        # 2. Brand + Intent (reviews, pricing, deals, etc.)
        for intent_name, templates in BRAND_INTENTS.items():
            if intent_name == 'comparison':
                continue  # Already handled above
            intent_kws = set()
            for brand in brands:
                for template in templates:
                    if '{other}' in template:
                        continue
                    kw = template.replace('{brand}', brand)
                    intent_kws.add(kw)
            universe.update(intent_kws)
            categories[intent_name] = {
                'total': len(intent_kws),
                'existing': len(intent_kws & existing),
                'gap': len(intent_kws - existing),
                'coverage_pct': round(len(intent_kws & existing) / max(1, len(intent_kws)) * 100, 1)
            }

        # 3. "Best X for Y" keywords
        use_cases = BEST_OF_USE_CASES.get(niche, [])
        niche_name = niche.replace('_', ' ')
        bestof_kws = set()
        for use_case in use_cases:
            bestof_kws.add(f"best {niche_name} for {use_case}")
            bestof_kws.add(f"best {niche_name} {use_case}")
            # Also brand-specific best-of
            for brand in brands[:10]:  # Top brands only
                bestof_kws.add(f"{brand} for {use_case}")
                bestof_kws.add(f"is {brand} good for {use_case}")
        universe.update(bestof_kws)
        categories['best_of'] = {
            'total': len(bestof_kws),
            'existing': len(bestof_kws & existing),
            'gap': len(bestof_kws - existing),
            'coverage_pct': round(len(bestof_kws & existing) / max(1, len(bestof_kws)) * 100, 1)
        }

        # 4. Problem/How-to keywords
        problem_kws = set(PROBLEM_KEYWORDS.get(niche, []))
        universe.update(problem_kws)
        categories['problems'] = {
            'total': len(problem_kws),
            'existing': len(problem_kws & existing),
            'gap': len(problem_kws - existing),
            'coverage_pct': round(len(problem_kws & existing) / max(1, len(problem_kws)) * 100, 1)
        }

        # Overall stats
        total_universe = len(universe)
        total_existing = len(universe & existing)
        total_gap = total_universe - total_existing

        # Get existing count for this niche from the CSV
        csv_niche_count = sum(1 for k in KEYWORDS if k.get('niche', '') == niche)

        # Estimate revenue for the gap keywords
        epv_by_type = {
            'deal': 1.18, 'comparison': 0.53, 'review': 0.31,
            'best_of': 0.16, 'informational': 0.31, 'other': 0.17
        }
        niche_multipliers = {
            'vpn': 1.5, 'identity_theft': 1.4, 'data_broker_removal': 1.3,
            'antivirus': 1.2, 'web_hosting': 1.3, 'email_marketing': 1.2,
            'parental_control': 1.1, 'home_security': 1.0, 'pet_insurance': 1.0,
            'gps_dog_fence': 1.0, 'credit_repair': 1.2
        }
        niche_mult = niche_multipliers.get(niche, 1.0)

        # Rough revenue estimate for gaps (conservative: assume avg 1000 volume, 10% capture)
        gap_revenue_estimates = {}
        for cat_name, cat_data in categories.items():
            cat_type = 'comparison' if cat_name == 'comparisons' else \
                       'review' if cat_name == 'review' else \
                       'deal' if cat_name == 'deal' else \
                       'best_of' if cat_name == 'best_of' else 'other'
            epv = epv_by_type.get(cat_type, 0.17)
            # Conservative: avg 500 volume, 10% capture, with willingness
            avg_rev_per_kw = 500 * 0.10 * epv * niche_mult * 0.6
            gap_revenue_estimates[cat_name] = round(cat_data['gap'] * avg_rev_per_kw, 0)

        # Top gap keywords (sample from each category)
        top_gaps = []
        for cat_name, cat_data in categories.items():
            if cat_name == 'comparisons':
                gap_set = comparison_kws - existing
            elif cat_name == 'best_of':
                gap_set = bestof_kws - existing
            elif cat_name == 'problems':
                gap_set = problem_kws - existing
            else:
                # Reconstruct intent gaps
                gap_set = set()
                templates = BRAND_INTENTS.get(cat_name, [])
                for brand in brands:
                    for template in templates:
                        if '{other}' not in template:
                            kw = template.replace('{brand}', brand)
                            if kw not in existing:
                                gap_set.add(kw)

            # Pick representative gaps
            sorted_gaps = sorted(gap_set)[:8]
            for g in sorted_gaps:
                top_gaps.append({
                    'keyword': g,
                    'category': cat_name,
                    'type': 'comparison' if cat_name == 'comparisons' else
                            'deal' if cat_name == 'deal' else
                            'review' if cat_name == 'review' else
                            'best_of' if cat_name == 'best_of' else 'other'
                })

        niches_analysis.append({
            'niche': niche,
            'brands': len(brands),
            'csvKeywords': csv_niche_count,
            'universeSize': total_universe,
            'existing': total_existing,
            'gap': total_gap,
            'coveragePct': round(total_existing / max(1, total_universe) * 100, 1),
            'categories': categories,
            'gapRevenueEstimates': gap_revenue_estimates,
            'totalGapRevenue': sum(gap_revenue_estimates.values()),
            'topGaps': top_gaps[:40],
            'nicheMult': niche_mult
        })

    # Sort by gap revenue (biggest opportunity first)
    niches_analysis.sort(key=lambda x: x['totalGapRevenue'], reverse=True)

    # Grand totals
    grand_universe = sum(n['universeSize'] for n in niches_analysis)
    grand_existing = sum(n['existing'] for n in niches_analysis)
    grand_gap = sum(n['gap'] for n in niches_analysis)
    grand_gap_revenue = sum(n['totalGapRevenue'] for n in niches_analysis)

    return jsonify({
        'success': True,
        'niches': niches_analysis,
        'grandTotals': {
            'totalUniverse': grand_universe,
            'totalExisting': grand_existing,
            'totalGap': grand_gap,
            'coveragePct': round(grand_existing / max(1, grand_universe) * 100, 1),
            'totalGapRevenue': grand_gap_revenue,
            'csvTotal': len(KEYWORDS)
        }
    })


# ============================================
# SMART PICKS - Guided keyword recommendations
# ============================================

def generate_video_title(keyword, keyword_type, niche):
    """Generate a suggested YouTube video title for a keyword."""
    kw_title = keyword.title()

    if keyword_type == 'comparison':
        parts = keyword.lower().replace(' or ', ' vs ').split(' vs ')
        if len(parts) == 2:
            a, b = parts[0].strip().title(), parts[1].strip().title()
            titles = [
                f"{a} vs {b} - Which One Should You ACTUALLY Get?",
                f"{a} vs {b} - Honest Comparison After Testing Both",
                f"I Tested {a} and {b} - Here's the Winner",
            ]
            return titles
        return [f"{kw_title} - Complete Comparison"]

    if keyword_type == 'review':
        brand = keyword.lower().replace('review', '').replace('reviews', '').strip().title()
        return [
            f"{brand} Review - Is It Worth Your Money in 2026?",
            f"My Honest {brand} Review After 6 Months",
            f"{brand} Review - Watch Before You Buy",
        ]

    if keyword_type == 'deal':
        brand = keyword.lower()
        for term in ['coupon', 'coupon code', 'discount', 'promo code', 'deal', 'sale']:
            brand = brand.replace(term, '').strip()
        brand = brand.title()
        return [
            f"{brand} Coupon Code - Get the BEST Deal Available",
            f"How to Get {brand} for the Cheapest Price (Working 2026)",
        ]

    if keyword_type == 'best_of':
        return [
            f"{kw_title} - Top 5 Picks Ranked",
            f"{kw_title} - My #1 Pick Will Surprise You",
        ]

    # Problem/informational keywords
    niche_solutions = {
        'vpn': 'a VPN',
        'identity_theft': 'identity theft protection',
        'data_broker_removal': 'a data removal service',
        'parental_control': 'parental controls',
        'home_security': 'a security system',
        'antivirus': 'antivirus software',
        'web_hosting': 'the right web host',
        'email_marketing': 'email marketing',
        'pet_insurance': 'pet insurance',
        'gps_dog_fence': 'a GPS dog fence',
        'credit_repair': 'credit repair',
    }
    solution = niche_solutions.get(niche, 'the right solution')
    return [
        f"{kw_title} - Here's What To Do",
        f"{kw_title} - How {solution.title()} Can Help",
    ]


def plain_english_reason(keyword_data, keyword_type):
    """Generate a plain-English explanation of why this keyword is a good pick."""
    reasons = []
    revenue = keyword_data.get('revenue', 0)
    volume = keyword_data.get('volume', 0)
    pattern = keyword_data.get('ytPattern', 'no_data')
    willingness = keyword_data.get('willingness', 0.5)
    trend = keyword_data.get('trend', 'unknown')

    # Revenue
    if revenue >= 500:
        reasons.append(f"High earning potential (${revenue:.0f}/mo est.)")
    elif revenue >= 100:
        reasons.append(f"Solid earning potential (${revenue:.0f}/mo est.)")
    elif revenue > 0:
        reasons.append(f"Moderate earning potential (${revenue:.0f}/mo est.)")

    # Volume
    if volume >= 10000:
        reasons.append(f"Lots of people search this ({volume:,}/mo)")
    elif volume >= 3000:
        reasons.append(f"Good search volume ({volume:,}/mo)")
    elif volume >= 1000:
        reasons.append(f"Decent search volume ({volume:,}/mo)")

    # Competition
    if pattern == 'distributed':
        reasons.append("Low competition - easier to rank")
    elif pattern == 'top_heavy':
        reasons.append("Moderate competition - quality content can win")
    elif pattern == 'winner_take_all':
        reasons.append("Competitive - but high reward if you rank")

    # Buyer intent
    if willingness >= 0.8:
        reasons.append("Searchers are ready to buy")
    elif willingness >= 0.6:
        reasons.append("Good buyer intent")

    # Trend
    if trend == 'rising':
        reasons.append("Trending up right now")
    elif trend == 'declining':
        reasons.append("Caution: search interest is declining")

    # Keyword type advantage
    if keyword_type == 'deal':
        reasons.append("Deal seekers convert extremely well")
    elif keyword_type == 'comparison':
        reasons.append("People comparing products are close to buying")
    elif keyword_type == 'review':
        reasons.append("Review searchers are evaluating a purchase")

    return reasons


@app.route('/api/smart-picks')
@login_required
@cache_response('smart_picks', ttl_seconds=600)  # 10 min cache
def smart_picks():
    """
    Beginner-friendly keyword recommendations.
    No jargon. Clear ranking. Video title suggestions.
    """
    niche_filter = request.args.get('niche', '')

    user = get_current_user()
    user_email = user.get('email', 'anonymous') if user else 'anonymous'

    labels = {}
    yt_db = {}
    trends = {}
    votes = {}

    try:
        conn = get_db()
        c = conn.cursor()

        # Get labels
        c.execute('SELECT keyword, label, is_favorite FROM keyword_labels')
        labels = {row[0]: {'label': row[1], 'favorite': bool(row[2])} for row in c.fetchall()}

        # Get YT data
        c.execute('SELECT keyword, yt_avg_views, yt_view_pattern FROM keyword_yt_data')
        yt_db = {row[0].lower(): {'avg_views': row[1], 'view_pattern': row[2]} for row in c.fetchall()}

        # Get trends
        c.execute('SELECT keyword, trend, trend_change_pct, current_interest, peak_months, seasonality_score, publish_window FROM keyword_trends')
        trends = {row[0].lower(): {'trend': row[1], 'change': row[2], 'interest': row[3], 'peakMonths': row[4], 'seasonalityScore': row[5] or 0, 'publishWindow': row[6]} for row in c.fetchall()}

        # Get vote scores
        c.execute('''
            SELECT keyword,
                   COALESCE(SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END), 0) -
                   COALESCE(SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END), 0) as score
            FROM keyword_votes GROUP BY keyword
        ''')
        votes = {row[0]: row[1] for row in c.fetchall()}

        release_db(conn)
    except Exception as e:
        print(f"[SMART-PICKS] DB unavailable, using in-memory data only: {e}")

    picks = []
    for k in KEYWORDS:
        keyword = k['keyword']
        keyword_lower = keyword.lower()
        niche = k.get('niche', 'general')

        if niche_filter and niche != niche_filter:
            continue

        volume = k.get('volume', 0) or 0
        yt_data = yt_db.get(keyword_lower, {})
        pattern = yt_data.get('view_pattern') or k.get('ytPattern', 'no_data') or 'no_data'
        avg_views = yt_data.get('avg_views') or k.get('ytViews', 0) or 0

        keyword_type = classify_keyword_type(keyword)
        willingness = estimate_willingness_to_spend(keyword, keyword_type, niche)

        # Revenue calculation
        epv_by_type = {
            'deal': 1.18, 'comparison': 0.53, 'review': 0.31,
            'best_of': 0.16, 'informational': 0.31, 'other': 0.17
        }
        niche_multipliers = {
            'vpn': 1.5, 'identity_theft': 1.4, 'data_broker_removal': 1.3,
            'antivirus': 1.2, 'web_hosting': 1.3, 'email_marketing': 1.2,
            'parental_control': 1.1, 'home_security': 1.0, 'pet_insurance': 1.0,
            'gps_dog_fence': 1.0, 'credit_repair': 1.2
        }
        capture_rates = {
            'distributed': 0.15, 'top_heavy': 0.08,
            'winner_take_all': 0.03, 'no_data': 0.10
        }
        epv = epv_by_type.get(keyword_type, 0.17) * niche_multipliers.get(niche, 1.0)
        capture = capture_rates.get(pattern, 0.10)
        revenue = volume * capture * epv * willingness

        trend_data = trends.get(keyword_lower, {})
        trend_dir = trend_data.get('trend', 'unknown')

        # ============================================
        # SMART SCORE (0-100) - Beginner-optimized
        # Weights what matters for someone starting out:
        #   - Low competition (easiest to rank)
        #   - Decent revenue (worth the effort)
        #   - High buyer intent (converts better)
        #   - Rising trend (growing opportunity)
        # ============================================
        smart_score = 0

        # Competition easiness (0-35 pts) — biggest weight for beginners
        comp_scores = {'distributed': 35, 'no_data': 20, 'top_heavy': 12, 'winner_take_all': 3}
        smart_score += comp_scores.get(pattern, 15)

        # Revenue potential (0-25 pts)
        if revenue >= 500: smart_score += 25
        elif revenue >= 200: smart_score += 20
        elif revenue >= 100: smart_score += 15
        elif revenue >= 50: smart_score += 10
        elif revenue >= 20: smart_score += 5

        # Buyer intent (0-20 pts)
        smart_score += min(20, willingness * 25)

        # Trend bonus (0-10 pts)
        if trend_dir == 'rising': smart_score += 10
        elif trend_dir == 'stable': smart_score += 5
        elif trend_dir == 'unknown': smart_score += 3

        # Seasonal timing bonus (0-5 pts)
        publish_window = trend_data.get('publishWindow')
        if publish_window:
            month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            current_month = month_names[datetime.now().month - 1]
            window_months = publish_window.split('-') if publish_window else []
            if current_month in window_months:
                smart_score += 5  # Approaching peak season
            elif trend_data.get('peakMonths') and current_month in trend_data.get('peakMonths', '').split(','):
                smart_score += 3  # Currently in peak

        # Keyword type bonus (0-10 pts) — deals/comparisons convert best
        type_scores = {'deal': 10, 'comparison': 8, 'review': 6, 'best_of': 4, 'informational': 1, 'other': 2}
        smart_score += type_scores.get(keyword_type, 2)

        # Team vote boost
        vote_score = votes.get(keyword, 0)
        if vote_score > 0:
            smart_score += min(5, vote_score * 2)

        smart_score = min(100, max(0, round(smart_score, 1)))

        # Difficulty label (plain English)
        if pattern == 'distributed':
            difficulty = 'Easy'
            difficulty_detail = 'Views are spread across many channels - you can break in'
        elif pattern == 'no_data':
            difficulty = 'Unknown'
            difficulty_detail = 'No YouTube data available yet'
        elif pattern == 'top_heavy':
            difficulty = 'Medium'
            difficulty_detail = 'A few channels dominate - need strong content to compete'
        else:
            difficulty = 'Hard'
            difficulty_detail = 'One channel owns most views - very competitive'

        # Money rating (1-5 dollar signs)
        if revenue >= 500: money_rating = 5
        elif revenue >= 200: money_rating = 4
        elif revenue >= 100: money_rating = 3
        elif revenue >= 50: money_rating = 2
        else: money_rating = 1

        # Prepare enriched data
        kw_data = {
            'revenue': revenue,
            'volume': volume,
            'ytPattern': pattern,
            'willingness': willingness,
            'trend': trend_dir,
        }

        reasons = plain_english_reason(kw_data, keyword_type)
        video_titles = generate_video_title(keyword, keyword_type, niche)

        label_data = labels.get(keyword, {})

        picks.append({
            'keyword': keyword,
            'niche': niche,
            'keywordType': keyword_type,
            'smartScore': smart_score,
            'difficulty': difficulty,
            'difficultyDetail': difficulty_detail,
            'moneyRating': money_rating,
            'revenue': round(revenue, 0),
            'volume': volume,
            'pattern': pattern,
            'willingness': round(willingness, 2),
            'trend': trend_dir,
            'trendChange': trend_data.get('change', 0),
            'peakMonths': trend_data.get('peakMonths'),
            'seasonalityScore': trend_data.get('seasonalityScore', 0),
            'publishWindow': trend_data.get('publishWindow'),
            'reasons': reasons,
            'videoTitles': video_titles,
            'contentAngle': k.get('contentAngle', ''),
            'label': label_data.get('label', 'none'),
            'favorite': label_data.get('favorite', False),
            'voteScore': vote_score,
        })

    # Sort by smart score
    picks.sort(key=lambda x: x['smartScore'], reverse=True)

    # Add rank
    for i, p in enumerate(picks):
        p['rank'] = i + 1

    # Niche summary for the filter
    niche_counts = {}
    for p in picks:
        n = p['niche']
        if n not in niche_counts:
            niche_counts[n] = {'count': 0, 'avgScore': 0, 'topRevenue': 0}
        niche_counts[n]['count'] += 1
        niche_counts[n]['avgScore'] += p['smartScore']
        niche_counts[n]['topRevenue'] = max(niche_counts[n]['topRevenue'], p['revenue'])

    niche_summary = []
    for n, data in niche_counts.items():
        data['avgScore'] = round(data['avgScore'] / data['count'], 1)
        niche_summary.append({'niche': n, **data})
    niche_summary.sort(key=lambda x: x['avgScore'], reverse=True)

    return jsonify({
        'success': True,
        'picks': picks,
        'nicheSummary': niche_summary,
        'total': len(picks)
    })


# ============================================
# BIGQUERY CACHE (Supabase)
# ============================================

def get_bq_cache(cache_key, max_age_hours=24):
    """Get cached BigQuery result from Supabase. Returns data dict or None."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT data, updated_at FROM bq_cache
            WHERE cache_key = %s AND updated_at > NOW() - INTERVAL '%s hours'
        ''', (cache_key, max_age_hours))
        row = c.fetchone()
        release_db(conn)
        if row:
            return {'data': row[0], 'updated_at': row[1].strftime('%Y-%m-%d %H:%M') if row[1] else None}
    except Exception as e:
        print(f"[BQ-CACHE] Read error for {cache_key}: {e}")
    return None


def set_bq_cache(cache_key, data):
    """Save BigQuery result to Supabase cache."""
    import json as _json
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO bq_cache (cache_key, data, updated_at)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (cache_key) DO UPDATE SET
                data = EXCLUDED.data,
                updated_at = CURRENT_TIMESTAMP
        ''', (cache_key, _json.dumps(data)))
        conn.commit()
        release_db(conn)
        print(f"[BQ-CACHE] Saved {cache_key}")
    except Exception as e:
        print(f"[BQ-CACHE] Write error for {cache_key}: {e}")


# ============================================
# CONTENT GAP ANALYSIS
# ============================================

@app.route('/api/content-gap/competitors')
@login_required
def content_gap_competitors():
    """Find top competitor channels from BigQuery SERP data."""
    from google.cloud import bigquery as bq

    silo_filter = request.args.get('silo', '').strip()
    refresh = request.args.get('refresh', '').lower() == 'true'

    # Check cache first (unless refresh requested)
    cache_key = f"content_gap_competitors:{silo_filter or 'all'}"
    if not refresh:
        cached = get_bq_cache(cache_key, max_age_hours=24)
        if cached:
            result = cached['data']
            result['cached'] = True
            result['cache_updated'] = cached['updated_at']
            return jsonify(result)

    client = get_bq_client()
    if not client:
        return jsonify({'success': False, 'error': 'BigQuery not available'}), 500
    ch_names_str = ', '.join(f"'{name}'" for name in ALL_BQ_CHANNEL_NAMES)

    # Fetch all tracked keywords from priority_keywords to distinguish true gaps vs not-ranking
    tracked_keywords = []
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT LOWER(keyword) FROM priority_keywords')
        tracked_keywords = [r[0] for r in c.fetchall()]
        release_db(conn)
    except Exception as e:
        print(f"[CONTENT-GAP] Error fetching tracked keywords: {e}")

    silo_clause = ""
    query_params = [bq.ArrayQueryParameter("tracked_kws", "STRING", tracked_keywords)]
    if silo_filter:
        silo_clause = "AND LOWER(Silo) = LOWER(@silo_filter)"
        query_params.append(bq.ScalarQueryParameter("silo_filter", "STRING", silo_filter))

    query = f"""
    WITH serp AS (
        SELECT
            LOWER(Keyword) as kw,
            Channel_title,
            Rank,
            Views,
            Silo,
            CASE WHEN Channel_title IN ({ch_names_str}) THEN 1 ELSE 0 END as is_digidom
        FROM {BQ_SERP_TABLE}
        WHERE Scrape_date = BQ_asia_scrape_date
          AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
          AND Scrape_date = (
              SELECT Scrape_date FROM (
                  SELECT Scrape_date, COUNT(*) as cnt
                  FROM {BQ_SERP_TABLE}
                  WHERE Scrape_date = BQ_asia_scrape_date
                    AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
                    AND Rank BETWEEN 1 AND 10
                  GROUP BY Scrape_date
                  HAVING cnt >= 1000
                  ORDER BY Scrape_date DESC
                  LIMIT 1
              )
          )
          AND Rank BETWEEN 1 AND 10
          AND Channel_title IS NOT NULL
          AND TRIM(Channel_title) != ''
          {silo_clause}
    ),
    digidom_kws AS (
        SELECT DISTINCT kw FROM serp WHERE is_digidom = 1
    ),
    tracked AS (
        SELECT DISTINCT kw FROM UNNEST(@tracked_kws) as kw
    )
    SELECT
        s.Channel_title,
        COUNT(DISTINCT s.kw) as keyword_count,
        COUNT(*) as total_appearances,
        AVG(s.Rank) as avg_rank,
        SUM(s.Views) as total_views,
        COUNT(DISTINCT CASE WHEN dk.kw IS NULL AND tk.kw IS NULL THEN s.kw END) as gap_count,
        COUNT(DISTINCT CASE WHEN dk.kw IS NULL AND tk.kw IS NOT NULL THEN s.kw END) as not_ranking_count,
        COUNT(DISTINCT CASE WHEN dk.kw IS NOT NULL THEN s.kw END) as overlap_count,
        (SELECT COUNT(*) FROM digidom_kws) - COUNT(DISTINCT CASE WHEN dk.kw IS NOT NULL THEN s.kw END) as win_count
    FROM serp s
    LEFT JOIN digidom_kws dk ON s.kw = dk.kw
    LEFT JOIN tracked tk ON s.kw = tk.kw
    WHERE s.is_digidom = 0
    GROUP BY s.Channel_title
    HAVING keyword_count >= {1 if silo_filter else 3}
    ORDER BY gap_count DESC, keyword_count DESC
    LIMIT 50
    """

    job_config = bq.QueryJobConfig(query_parameters=query_params) if query_params else None

    try:
        rows = client.query(query, job_config=job_config).result()
        competitors = []
        for row in rows:
            competitors.append({
                'channel': row.Channel_title,
                'keyword_count': row.keyword_count,
                'total_appearances': row.total_appearances,
                'avg_rank': round(row.avg_rank, 1),
                'total_views': row.total_views or 0,
                'gap_count': row.gap_count,
                'not_ranking_count': row.not_ranking_count,
                'overlap_count': row.overlap_count,
                'win_count': row.win_count,
            })

        # When loading all competitors (no silo filter), also get per-silo gap counts
        silo_counts = {}
        if not silo_filter:
            silo_query = f"""
            WITH serp AS (
                SELECT
                    LOWER(Keyword) as kw,
                    Channel_title,
                    Silo,
                    CASE WHEN Channel_title IN ({ch_names_str}) THEN 1 ELSE 0 END as is_digidom
                FROM {BQ_SERP_TABLE}
                WHERE Scrape_date = BQ_asia_scrape_date
                  AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
                  AND Scrape_date = (
                      SELECT Scrape_date FROM (
                          SELECT Scrape_date, COUNT(*) as cnt
                          FROM {BQ_SERP_TABLE}
                          WHERE Scrape_date = BQ_asia_scrape_date
                            AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
                            AND Rank BETWEEN 1 AND 10
                          GROUP BY Scrape_date
                          HAVING cnt >= 1000
                          ORDER BY Scrape_date DESC
                          LIMIT 1
                      )
                  )
                  AND Rank BETWEEN 1 AND 10
                  AND Channel_title IS NOT NULL
                  AND TRIM(Channel_title) != ''
                  AND Silo IS NOT NULL
                  AND TRIM(Silo) != ''
            ),
            digidom_kws AS (
                SELECT DISTINCT kw FROM serp WHERE is_digidom = 1
            ),
            tracked AS (
                SELECT DISTINCT kw FROM UNNEST(@tracked_kws) as kw
            )
            SELECT
                s.Silo,
                COUNT(DISTINCT s.Channel_title) as competitor_count,
                COUNT(DISTINCT CASE WHEN dk.kw IS NULL AND tk.kw IS NULL THEN s.kw END) as gap_keyword_count,
                COUNT(DISTINCT CASE WHEN dk.kw IS NULL AND tk.kw IS NOT NULL THEN s.kw END) as not_ranking_count
            FROM serp s
            LEFT JOIN digidom_kws dk ON s.kw = dk.kw
            LEFT JOIN tracked tk ON s.kw = tk.kw
            WHERE s.is_digidom = 0
            GROUP BY s.Silo
            ORDER BY gap_keyword_count DESC
            """
            try:
                silo_job_config = bq.QueryJobConfig(query_parameters=[bq.ArrayQueryParameter("tracked_kws", "STRING", tracked_keywords)])
                silo_rows = client.query(silo_query, job_config=silo_job_config).result()
                for sr in silo_rows:
                    silo_counts[sr.Silo] = {
                        'competitors': sr.competitor_count,
                        'gaps': sr.gap_keyword_count,
                        'not_ranking': sr.not_ranking_count,
                    }
            except Exception as se:
                print(f"[CONTENT-GAP] Silo counts query error: {se}")

        result = {'success': True, 'competitors': competitors, 'silo_counts': silo_counts}
        set_bq_cache(cache_key, result)
        return jsonify(result)
    except Exception as e:
        print(f"[CONTENT-GAP] Competitors query error: {e}")
        # Try stale cache as fallback
        stale = get_bq_cache(cache_key, max_age_hours=168)  # 7 day fallback
        if stale:
            result = stale['data']
            result['cached'] = True
            result['cache_updated'] = stale['updated_at']
            result['stale'] = True
            return jsonify(result)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/content-gap/analysis', methods=['POST'])
@login_required
def content_gap_analysis():
    """Side-by-side ranking comparison + gap identification."""
    from google.cloud import bigquery as bq
    import hashlib

    data = request.get_json()
    competitors = data.get('competitors', [])
    silo_filter = data.get('silo_filter', '')
    refresh = data.get('refresh', False)

    if not competitors:
        return jsonify({'success': False, 'error': 'Select at least one competitor'}), 400

    # Check cache first
    comp_hash = hashlib.md5(','.join(sorted(competitors)).encode()).hexdigest()[:8]
    cache_key = f"content_gap_analysis:{comp_hash}:{silo_filter or 'all'}"
    if not refresh:
        cached = get_bq_cache(cache_key, max_age_hours=24)
        if cached:
            result = cached['data']
            result['cached'] = True
            result['cache_updated'] = cached['updated_at']
            return jsonify(result)

    client = get_bq_client()
    if not client:
        return jsonify({'success': False, 'error': 'BigQuery not available'}), 500

    ch_names_str = ', '.join(f"'{name}'" for name in ALL_BQ_CHANNEL_NAMES)
    comp_params = [bq.ScalarQueryParameter(f"comp_{i}", "STRING", c) for i, c in enumerate(competitors)]
    comp_placeholders = ', '.join(f"@comp_{i}" for i in range(len(competitors)))

    silo_clause = ""
    extra_params = []
    if silo_filter:
        silo_clause = "AND LOWER(Silo) = LOWER(@silo_filter)"
        extra_params.append(bq.ScalarQueryParameter("silo_filter", "STRING", silo_filter))

    query = f"""
    WITH serp AS (
        SELECT
            LOWER(Keyword) as keyword,
            Channel_title,
            Rank,
            Views,
            Search_Volume,
            Silo
        FROM {BQ_SERP_TABLE}
        WHERE Scrape_date = BQ_asia_scrape_date
          AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
          AND Scrape_date = (
              SELECT Scrape_date FROM (
                  SELECT Scrape_date, COUNT(*) as cnt
                  FROM {BQ_SERP_TABLE}
                  WHERE Scrape_date = BQ_asia_scrape_date
                    AND Scrape_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
                    AND Rank BETWEEN 1 AND 10
                  GROUP BY Scrape_date
                  HAVING cnt >= 1000
                  ORDER BY Scrape_date DESC
                  LIMIT 1
              )
          )
          AND Rank BETWEEN 1 AND 10
          AND (Channel_title IN ({ch_names_str}) OR Channel_title IN ({comp_placeholders}))
          {silo_clause}
    ),
    digidom_ranks AS (
        SELECT keyword, MIN(Rank) as best_rank, MAX(Views) as best_views
        FROM serp WHERE Channel_title IN ({ch_names_str})
        GROUP BY keyword
    ),
    competitor_ranks AS (
        SELECT keyword, Channel_title as competitor, MIN(Rank) as best_rank, MAX(Views) as best_views
        FROM serp WHERE Channel_title IN ({comp_placeholders})
        GROUP BY keyword, Channel_title
    ),
    all_keywords AS (
        SELECT keyword, MAX(Search_Volume) as search_volume, MAX(Silo) as silo
        FROM serp
        GROUP BY keyword
    )
    SELECT
        ak.keyword, ak.search_volume, ak.silo,
        dr.best_rank as digidom_rank, dr.best_views as digidom_views,
        cr.competitor, cr.best_rank as comp_rank, cr.best_views as comp_views
    FROM all_keywords ak
    LEFT JOIN digidom_ranks dr ON ak.keyword = dr.keyword
    LEFT JOIN competitor_ranks cr ON ak.keyword = cr.keyword
    ORDER BY ak.search_volume DESC NULLS LAST, ak.keyword
    """

    job_config = bq.QueryJobConfig(query_parameters=comp_params + extra_params)

    try:
        rows = client.query(query, job_config=job_config).result()

        keyword_map = {}
        for row in rows:
            kw = row.keyword
            if kw not in keyword_map:
                keyword_map[kw] = {
                    'keyword': kw,
                    'search_volume': row.search_volume or 0,
                    'silo': row.silo or '',
                    'digidom_rank': row.digidom_rank,
                    'digidom_views': row.digidom_views or 0,
                    'competitors': {},
                }
            if row.competitor:
                keyword_map[kw]['competitors'][row.competitor] = {
                    'rank': row.comp_rank,
                    'views': row.comp_views or 0,
                }

        gap_keywords = []
        not_ranking_keywords = []
        winning_keywords = []
        overlap_keywords = []

        existing_kw_set = set(k['keyword'].lower().strip() for k in KEYWORDS)

        for kw, info in keyword_map.items():
            has_digidom = info['digidom_rank'] is not None
            has_competitor = len(info['competitors']) > 0
            keyword_type = classify_keyword_type(kw)

            entry = {
                'keyword': kw,
                'search_volume': info['search_volume'],
                'silo': info['silo'],
                'digidom_rank': info['digidom_rank'],
                'digidom_views': info['digidom_views'],
                'competitors': info['competitors'],
                'keyword_type': keyword_type,
                'in_library': kw in existing_kw_set,
            }

            if has_competitor and not has_digidom:
                if kw in existing_kw_set:
                    not_ranking_keywords.append(entry)
                else:
                    gap_keywords.append(entry)
            elif has_digidom and not has_competitor:
                winning_keywords.append(entry)
            elif has_digidom and has_competitor:
                overlap_keywords.append(entry)

        gap_keywords.sort(key=lambda x: x['search_volume'], reverse=True)
        not_ranking_keywords.sort(key=lambda x: x['search_volume'], reverse=True)

        # Enrich top 30 gap keywords with revenue estimates
        for gk in gap_keywords[:30]:
            yt_data = {'view_pattern': 'distributed', 'avg_views': 0, 'video_count': 0}
            comp_views = [c['views'] for c in gk['competitors'].values() if c['views']]
            if comp_views:
                yt_data['avg_views'] = sum(comp_views) / len(comp_views)

            kw_data = {'volume': gk['search_volume']}
            revenue = estimate_revenue_potential(kw_data, yt_data, gk['silo'] or 'general', gk['keyword'])
            gk['revenue_estimate'] = revenue['moderate']
            gk['revenue_conservative'] = revenue['conservative']
            gk['revenue_optimistic'] = revenue['optimistic']
            gk['keyword_type'] = revenue['keyword_type']
            gk['capture_rate'] = revenue['capture_rate']
            gk['opportunity_score'] = calculate_opportunity_score(kw_data, yt_data)

        overlap_keywords.sort(key=lambda x: (x['digidom_rank'] or 99))

        total_gap_volume = sum(g['search_volume'] for g in gap_keywords)
        total_gap_revenue = sum(g.get('revenue_estimate', 0) for g in gap_keywords[:30])

        print(f"[CONTENT-GAP] Analysis complete: {len(gap_keywords)} gaps, {len(not_ranking_keywords)} not ranking, {len(overlap_keywords)} overlap, {len(winning_keywords)} winning")

        result = {
            'success': True,
            'competitors': competitors,
            'gap_keywords': gap_keywords[:100],
            'not_ranking_keywords': not_ranking_keywords[:100],
            'winning_keywords': winning_keywords[:50],
            'overlap_keywords': overlap_keywords[:100],
            'summary': {
                'total_keywords_compared': len(keyword_map),
                'gap_count': len(gap_keywords),
                'not_ranking_count': len(not_ranking_keywords),
                'winning_count': len(winning_keywords),
                'overlap_count': len(overlap_keywords),
                'total_gap_volume': total_gap_volume,
                'top_30_gap_revenue': round(total_gap_revenue, 0),
            },
        }
        set_bq_cache(cache_key, result)
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[CONTENT-GAP] Analysis error: {e}")
        # Try stale cache as fallback
        stale = get_bq_cache(cache_key, max_age_hours=168)
        if stale:
            result = stale['data']
            result['cached'] = True
            result['cache_updated'] = stale['updated_at']
            result['stale'] = True
            return jsonify(result)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/content-gap/enrich', methods=['POST'])
@login_required
def content_gap_enrich():
    """Enrich selected gap keywords with volume/competition/trends data."""
    data = request.get_json()
    keywords = data.get('keywords', [])[:20]

    if not keywords:
        return jsonify({'success': False, 'error': 'No keywords provided'}), 400

    results = {}

    # Get volume/competition data
    vol_data = get_keyword_data_with_fallback(keywords)
    if vol_data.get('success') and vol_data.get('data'):
        for item in vol_data['data']:
            kw = item.get('keyword', '').lower()
            cpc_val = item.get('cpc', 0)
            if isinstance(cpc_val, dict):
                cpc_val = cpc_val.get('value', '0')
            results[kw] = {
                'volume': item.get('vol', 0),
                'cpc': cpc_val,
                'competition': item.get('competition', 0),
                'source': vol_data.get('source', 'unknown'),
            }

    # Get trend data for top keywords
    for kw in keywords[:10]:
        trend_data = get_serpapi_google_trends(kw)
        kw_lower = kw.lower()
        if kw_lower not in results:
            results[kw_lower] = {}
        results[kw_lower]['trend'] = trend_data.get('trend', 'unknown')
        results[kw_lower]['trend_change_pct'] = trend_data.get('trend_change_pct', 0)
        results[kw_lower]['current_interest'] = trend_data.get('current_interest', 0)

    # Get related keywords for top 3
    related = {}
    for kw in keywords[:3]:
        rel_data = get_related_keywords_with_fallback(kw)
        if rel_data.get('success'):
            related[kw.lower()] = rel_data.get('related', [])[:10]

    return jsonify({
        'success': True,
        'enriched': results,
        'related_keywords': related,
        'source': vol_data.get('source', 'none') if vol_data else 'none',
    })


# ============================================
# CHATBOT - Claude AI Fallback
# ============================================
CHATBOT_SYSTEM_PROMPT = """You are a helpful assistant for the KW Command Center, a YouTube keyword research and ranking tracker tool. Answer questions about how to use the app's features. Be concise and friendly. Use plain text (no markdown).

The app has these tabs and features:

1. **Smart Picks** (default tab) - AI-powered keyword recommendations. Click "Show Me the Best Keywords", filter by niche, sort by Best Overall/Highest Revenue/Easiest to Rank.

2. **Research** tab has 3 sub-features:
   - Seed Keyword Research: Enter a seed keyword + select niche, click "Research Keyword" to find related keywords
   - Trending Topics Not Covered: Click "Discover Trending Gaps" to find rising Google Trends topics you haven't covered
   - Channel Keyword Analysis: Enter a YouTube channel name/handle to analyze their keyword strategy. Can add keywords to your library.

3. **Keyword Library** - Browse/manage all 20K+ keywords. Features:
   - Filter by niche, tier (A/B/C/D), label (Interested/Maybe/Not Interested/Favorites), source
   - Search box to find specific keywords
   - Action buttons on each keyword: Star (favorite), checkmark (interested), X (not interested), ? (maybe), notes, comments, vote up/down
   - "+ Add Keywords" button to add custom keywords
   - "Collect Trends" to update Google Trends data
   - "Export CSV" to download keywords

4. **Domination Score** - Tracks your YouTube SERP positions for priority keywords.
   - Click "Load Ranking Data" or "Refresh Domination Score"
   - Import rankings from check_rankings.py script via "Import Results JSON"
   - "Manage Keywords" opens the keyword manager to activate/deactivate priority keywords, set primary/secondary relationships, assign silos
   - Domination formula: Position 1 = 50%, Pos 2 = 25%, Pos 3 = 15%, Pos 4&5 = 5% each
   - Click any keyword row to see history chart

5. **Content Planner** - Strategic video planning based on domination scores.
   - Click "Load Content Plan" to see how many videos needed per keyword
   - Priority levels: Critical (<75%), High (75-89%), Medium (90-99%), Maintain (100%)

6. **Analytics** - Revenue model calibrated from actual data. Shows revenue by keyword type.

7. **$3K Finder** - Find keywords most likely to earn $3,000/month each.
   - Click "Analyze All Keywords"
   - Filters: Top 10, Top 25, Realistic ($1K+), Rising Trends, Deals, Comparisons, Low Comp + High Rev

8. **Universe Map** - See all possible keywords in your niches and find gaps.
   - Click "Map the Universe" to see coverage per niche

9. **Content Gap** - Compare your keyword coverage against YouTube competitors.
   - Click "Discover Top Competitors" first, select competitors, then "Analyze Content Gaps"
   - Views: Gaps (they rank, you don't), Overlap (both rank), Winning (you rank, they don't)

General tips:
- Silos/niches include: VPN, Home Security, Identity Theft, Pet Insurance, etc.
- Primary keywords track your main ranking targets. Secondary keywords support them.
- The "NEW" badge means a keyword has no audit data yet.
- Data loads from Supabase on startup (takes about a minute).
- Use the niche/silo dropdown to filter data across most tabs.

If the question is completely unrelated to the app, politely say you can only help with the KW Command Center."""

@app.route('/api/chatbot', methods=['POST'])
@login_required
def chatbot_ask():
    """Claude AI chatbot fallback when FAQ can't answer."""
    try:
        data = request.get_json()
        question = data.get('question', '').strip()
        if not question:
            return jsonify({'success': False, 'error': 'No question provided'}), 400

        if not anthropic:
            return jsonify({
                'success': True,
                'answer': "The AI assistant package isn't installed. Please contact your admin.",
                'source': 'error'
            })

        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({
                'success': True,
                'answer': "I'm sorry, the AI assistant isn't configured yet. Please check the FAQ suggestions or ask your admin to add the ANTHROPIC_API_KEY.",
                'source': 'error'
            })

        client = anthropic.Anthropic(api_key=api_key, timeout=30.0)
        message = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=300,
            system=CHATBOT_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": question}]
        )

        answer = message.content[0].text
        return jsonify({'success': True, 'answer': answer, 'source': 'claude'})

    except Exception as e:
        print(f"[CHATBOT ERROR] {e}")
        return jsonify({'success': True, 'answer': "Sorry, I'm having trouble right now. Try again in a moment!", 'source': 'error'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
