#!/usr/bin/env python3
"""
Migrate SQLite data to Supabase Postgres.
Run this once from a machine with network access to Supabase.

Usage: DATABASE_URL="postgresql://..." python migrate_to_supabase.py
"""

import os
import sys
import sqlite3
import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:bky!o!TK6*8G@db.nqleuhmuhsnkcvherbku.supabase.co:5432/postgres')
SQLITE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'keyword_data.db')


def create_tables(pg):
    """Create all tables in Postgres (Supabase)"""
    c = pg.cursor()

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

    pg.commit()
    print("[TABLES] All tables created successfully")


def migrate_table(sqlite_conn, pg_conn, table_name, columns):
    """Migrate data from a SQLite table to Postgres"""
    sc = sqlite_conn.cursor()
    pc = pg_conn.cursor()

    # Check if Postgres table already has data
    pc.execute(f'SELECT COUNT(*) FROM {table_name}')
    existing = pc.fetchone()[0]
    if existing > 0:
        print(f"  [{table_name}] Already has {existing} rows, skipping")
        return

    # Get data from SQLite
    sc.execute(f'SELECT {", ".join(columns)} FROM {table_name}')
    rows = sc.fetchall()

    if not rows:
        print(f"  [{table_name}] No data to migrate")
        return

    # Batch insert into Postgres
    placeholders = ', '.join(['%s'] * len(columns))
    cols = ', '.join(columns)
    insert_sql = f'INSERT INTO {table_name} ({cols}) VALUES ({placeholders}) ON CONFLICT DO NOTHING'

    batch_size = 500
    total = 0
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i+batch_size]
        psycopg2.extras.execute_batch(pc, insert_sql, batch)
        total += len(batch)

    pg_conn.commit()
    print(f"  [{table_name}] Migrated {total} rows")


def main():
    if not os.path.exists(SQLITE_PATH):
        print(f"SQLite database not found at {SQLITE_PATH}")
        sys.exit(1)

    print(f"[START] Connecting to Supabase...")
    pg = psycopg2.connect(DATABASE_URL)
    sqlite_conn = sqlite3.connect(SQLITE_PATH)

    print("[STEP 1] Creating tables...")
    create_tables(pg)

    print("[STEP 2] Migrating data...")

    migrate_table(sqlite_conn, pg, 'keywords_master', [
        'keyword', 'niche', 'funnel', 'intent_type', 'volume', 'commission',
        'revenue_potential', 'buying_intent', 'yt_avg_monthly_views', 'yt_view_pattern',
        'priority_score', 'opportunity_tier', 'competition', 'content_angle', 'rationale',
        'conversion_likelihood', 'time_to_convert', 'problem_type', 'urgency_score',
        'yt_top_video_title', 'yt_top_video_views', 'yt_top_video_channel',
        'added_by_email', 'added_by_name', 'source'
    ])

    migrate_table(sqlite_conn, pg, 'keyword_labels', [
        'keyword', 'label', 'is_favorite', 'notes',
        'label_updated_by', 'favorite_updated_by', 'notes_updated_by'
    ])

    migrate_table(sqlite_conn, pg, 'keyword_yt_data', [
        'keyword', 'yt_avg_views', 'yt_view_pattern',
        'yt_top_video_title', 'yt_top_video_views', 'yt_top_video_channel',
        'yt_total_views', 'yt_video_count'
    ])

    migrate_table(sqlite_conn, pg, 'keyword_votes', [
        'keyword', 'user_email', 'user_name', 'vote'
    ])

    migrate_table(sqlite_conn, pg, 'keyword_comments', [
        'keyword', 'user_email', 'user_name', 'comment'
    ])

    migrate_table(sqlite_conn, pg, 'keyword_additions', [
        'keyword', 'user_email', 'user_name', 'source', 'source_detail'
    ])

    migrate_table(sqlite_conn, pg, 'keyword_trends', [
        'keyword', 'trend', 'trend_change_pct', 'current_interest', 'data_points'
    ])

    migrate_table(sqlite_conn, pg, 'ranking_history', [
        'keyword', 'revenue', 'domination_score', 'positions_owned'
    ])

    migrate_table(sqlite_conn, pg, 'researched_keywords', [
        'keyword', 'seed_keyword', 'source', 'search_volume', 'keyword_difficulty',
        'cpc', 'competition', 'yt_total_views', 'yt_avg_views', 'yt_video_count',
        'yt_top_channel', 'yt_view_pattern', 'revenue_potential', 'priority_score',
        'opportunity_tier', 'niche', 'funnel_stage'
    ])

    sqlite_conn.close()
    pg.close()

    print("\n[DONE] Migration complete! Your Supabase database is ready.")
    print("Set DATABASE_URL in Railway environment variables to start using it.")


if __name__ == '__main__':
    main()
