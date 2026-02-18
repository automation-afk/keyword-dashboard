-- Run this in Supabase SQL Editor to create all tables
-- Dashboard → SQL Editor → New Query → Paste this → Run

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
);

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
);

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
);

CREATE TABLE IF NOT EXISTS ranking_history (
    id SERIAL PRIMARY KEY,
    keyword TEXT NOT NULL,
    revenue DOUBLE PRECISION,
    domination_score DOUBLE PRECISION,
    positions_owned TEXT,
    snapshot_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domination_audits (
    id SERIAL PRIMARY KEY,
    audit_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS keyword_dom_targets (
    keyword TEXT PRIMARY KEY,
    target_dom_score INTEGER DEFAULT 100,
    updated_by TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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
);

CREATE TABLE IF NOT EXISTS keyword_votes (
    id SERIAL PRIMARY KEY,
    keyword TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_name TEXT,
    vote INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(keyword, user_email)
);

CREATE TABLE IF NOT EXISTS keyword_comments (
    id SERIAL PRIMARY KEY,
    keyword TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_name TEXT,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS keyword_additions (
    id SERIAL PRIMARY KEY,
    keyword TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_name TEXT,
    source TEXT DEFAULT 'manual',
    source_detail TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(keyword, user_email)
);

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
);

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
);

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
    is_primary BOOLEAN DEFAULT FALSE,
    parent_keyword TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Disable RLS so the app can read/write without policies
ALTER TABLE keyword_labels ENABLE ROW LEVEL SECURITY;
ALTER TABLE keywords_master ENABLE ROW LEVEL SECURITY;
ALTER TABLE keyword_votes ENABLE ROW LEVEL SECURITY;
ALTER TABLE keyword_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE keyword_additions ENABLE ROW LEVEL SECURITY;
ALTER TABLE keyword_trends ENABLE ROW LEVEL SECURITY;
ALTER TABLE keyword_yt_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE ranking_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE researched_keywords ENABLE ROW LEVEL SECURITY;
ALTER TABLE revenue_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE priority_keywords ENABLE ROW LEVEL SECURITY;

-- Create policies to allow all operations (the app handles auth via Flask sessions)
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY[
        'keyword_labels', 'keywords_master', 'keyword_votes', 'keyword_comments',
        'keyword_additions', 'keyword_trends', 'keyword_yt_data', 'ranking_history',
        'researched_keywords', 'revenue_data', 'priority_keywords'
    ]) LOOP
        EXECUTE format('DROP POLICY IF EXISTS "allow_all" ON %I', t);
        EXECUTE format('CREATE POLICY "allow_all" ON %I FOR ALL USING (true) WITH CHECK (true)', t);
    END LOOP;
END $$;
