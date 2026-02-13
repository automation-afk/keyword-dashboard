# Keyword Research & Channel Analysis Tool
## Technical Specification & Project Plan

---

## 1. Project Overview

### 1.1 Purpose
A keyword research and competitive intelligence tool for YouTube affiliate marketers. Helps identify profitable keywords, analyze competitor channels, track keyword performance, and plan content strategy.

### 1.2 Target User
YouTube creators in affiliate marketing niches (VPN, mattress, software, etc.) who need to:
- Discover high-value keywords to target
- Analyze what competitors are publishing
- Track which keywords they've covered vs. gaps
- Prioritize content based on revenue potential

### 1.3 Core Value Proposition
- **Channel Analysis**: Scrape ANY YouTube channel to extract their keyword strategy
- **Smart Keyword Extraction**: Parse video titles to identify target keywords
- **Revenue Modeling**: Estimate earnings potential using calibrated EPV model
- **Content Planning**: Track coverage and identify gaps

---

## 2. Feature Specification

### 2.1 Channel Keyword Analysis (Primary Feature)

**Input**: YouTube channel handle (@name), URL, or channel name

**Output**:
| Data Point | Description |
|------------|-------------|
| All Videos | Complete video list with titles, views, publish dates |
| Extracted Keywords | Target keyword parsed from each title |
| Keyword Frequency | How many videos target each keyword |
| Niche Detection | Auto-categorize keywords (VPN, mattress, etc.) |
| Keyword Type | Classification (review, comparison, best-of, deal) |
| View Distribution | Pattern analysis (distributed/top-heavy/winner-take-all) |
| Conversion Immediacy | Purchase intent (high/medium/low) |
| Revenue Potential | Estimated $/month based on views and EPV |
| Republish Analysis | Keywords updated frequently (last 12 months) |
| Hot Keywords | Keywords with 2+ videos in past year |

**Keyword Extraction Logic**:
```
1. Split title on separators: | - :
2. Take first meaningful segment
3. Normalize "Top N" → "Best"
4. Remove year suffixes (2024, 2025)
5. Remove filler words (the, a, an, for)
6. Preserve brand spelling exactly
7. Detect keyword type and niche
```

### 2.2 Keyword Library

**Purpose**: Central repository of all keywords being tracked

**Fields per Keyword**:
- Keyword text
- Search volume (from SEO API)
- Keyword difficulty
- CPC
- YouTube metrics (avg views, video count, view pattern)
- Revenue potential (calculated)
- Opportunity tier (A/B/C/D)
- Niche
- User labels (interested/not interested/researching)
- Favorite flag
- Notes

**Features**:
- Filter by niche, tier, label
- Sort by any column
- Search
- Bulk actions

### 2.3 Seed Keyword Research

**Input**: Seed keyword + niche

**Process**:
1. Get search volume/difficulty from SEO API (DataForSEO)
2. Scrape YouTube for top videos
3. Analyze view distribution
4. Calculate opportunity score
5. Generate related keywords
6. Estimate revenue potential

**Output**: Keyword data + related keywords + YouTube analysis

### 2.4 Domination Score

**Purpose**: Track coverage of keywords in your niche

**Metrics**:
- Keywords covered vs. total
- Revenue captured vs. potential
- Gaps (high-value keywords not covered)
- Recommendations for next videos

### 2.5 Content Planner

**Purpose**: Prioritize what to film next

**Inputs**:
- Domination score data
- Keyword library with labels
- Revenue potential

**Output**: Prioritized list of keywords to target

---

## 3. Technical Architecture

### 3.1 Stack
```
Backend:  Python/Flask
Database: SQLite
Frontend: Vanilla HTML/CSS/JS (no framework)
Hosting:  Railway (or any PaaS)
```

### 3.2 External APIs

| API | Purpose | Key Endpoints |
|-----|---------|---------------|
| YouTube Data API v3 | Fetch all channel videos + view counts | channels.list, playlistItems.list, videos.list |
| SerpAPI | YouTube search, Google search | youtube search, google search |
| DataForSEO | Search volume, keyword difficulty | keywords_data/google |

### 3.3 API Rate Limits & Costs
- YouTube API: 10,000 quota units/day (free)
- SerpAPI: 100 searches/month (free tier)
- DataForSEO: Pay per request (~$0.01/keyword)

---

## 4. Database Schema

### 4.1 Tables

```sql
-- Core keyword storage
CREATE TABLE researched_keywords (
    id INTEGER PRIMARY KEY,
    keyword TEXT NOT NULL,
    seed_keyword TEXT,
    source TEXT,  -- 'seed', 'related', 'channel_analysis'
    search_volume INTEGER,
    keyword_difficulty FLOAT,
    cpc FLOAT,
    competition TEXT,
    yt_total_views INTEGER,
    yt_avg_views INTEGER,
    yt_video_count INTEGER,
    yt_top_channel TEXT,
    yt_view_pattern TEXT,  -- 'distributed', 'top_heavy', 'winner_take_all'
    revenue_potential FLOAT,
    priority_score FLOAT,
    opportunity_tier TEXT,  -- 'A', 'B', 'C', 'D'
    niche TEXT,
    funnel_stage TEXT,
    researched_at TIMESTAMP,
    UNIQUE(keyword, source)
);

-- YouTube data cache
CREATE TABLE keyword_yt_data (
    id INTEGER PRIMARY KEY,
    keyword TEXT UNIQUE NOT NULL,
    yt_avg_views INTEGER,
    yt_view_pattern TEXT,
    yt_top_video_title TEXT,
    yt_top_video_views INTEGER,
    yt_top_video_channel TEXT,
    yt_total_views INTEGER,
    yt_video_count INTEGER,
    updated_at TIMESTAMP
);

-- User labels and preferences
CREATE TABLE keyword_labels (
    keyword TEXT PRIMARY KEY,
    label TEXT DEFAULT 'none',  -- 'interested', 'not_interested', 'researching'
    is_favorite BOOLEAN DEFAULT FALSE,
    notes TEXT,
    updated_at TIMESTAMP
);

-- Revenue tracking (optional)
CREATE TABLE revenue_data (
    id INTEGER PRIMARY KEY,
    keyword TEXT NOT NULL,
    video_url TEXT,
    video_views INTEGER,
    affiliate_clicks INTEGER,
    conversions INTEGER,
    revenue FLOAT,
    period_start DATE,
    period_end DATE,
    created_at TIMESTAMP
);
```

---

## 5. API Endpoints

### 5.1 Channel Analysis
```
POST /api/channel/analyze
Body: { "channel": "@channelname" }
Returns: {
    success: bool,
    channel: string,
    total_videos: int,
    videos: [...],
    keyword_patterns: [...],
    hot_keywords: [...],
    publishing_stats: {...},
    republish_analysis: [...]
}

POST /api/channel/add-to-library
Body: { "keywords": [...], "channel": "source" }
Returns: { success: bool, added: int, skipped: int }
```

### 5.2 Keyword Research
```
POST /api/research
Body: { "keyword": "best vpn", "niche": "vpn" }
Returns: { keyword_data, youtube_data, related_keywords, revenue_estimate }
```

### 5.3 Library Management
```
GET  /api/keywords              -- List all keywords
POST /api/label                 -- Set keyword label
POST /api/favorite              -- Toggle favorite
GET  /api/keywords/export       -- Export to CSV
```

### 5.4 Analytics
```
GET /api/domination             -- Domination score
GET /api/revenue/analysis       -- Revenue analytics
```

---

## 6. Key Algorithms

### 6.1 Keyword Extraction from Title
```python
def extract_target_keyword(title):
    # 1. Split on separators
    segments = re.split(r'\s*[\|\-\:\—\–]\s*', title)

    # 2. Take first meaningful segment
    segment = segments[0].strip()

    # 3. Normalize "Top N" to "Best"
    segment = re.sub(r'^top\s+\d+\s+', 'Best ', segment, flags=re.I)

    # 4. Remove year at end
    segment = re.sub(r'\s*\(?\d{4}\)?$', '', segment)

    # 5. Remove filler words
    segment = re.sub(r'^(the|a|an)\s+', '', segment, flags=re.I)

    # 6. Detect type and niche
    keyword_type = classify_keyword_type(segment)
    niche = detect_niche(segment)

    return {
        'keyword': segment,
        'keyword_type': keyword_type,
        'niche': niche
    }
```

### 6.2 View Pattern Analysis
```python
def determine_view_pattern(view_counts):
    """Analyze how views are distributed across videos"""
    if len(view_counts) < 3:
        return 'no_data'

    total = sum(view_counts)
    top_share = view_counts[0] / total
    top3_share = sum(view_counts[:3]) / total

    if top_share > 0.5:
        return 'winner_take_all'  # One video dominates
    elif top3_share > 0.7:
        return 'top_heavy'        # Top 3 dominate
    else:
        return 'distributed'      # Views spread out
```

### 6.3 Revenue Estimation
```python
def estimate_revenue_potential(avg_views, keyword_type, niche, view_pattern):
    """
    Formula: Monthly Revenue = Traffic × Capture Rate × EPV

    EPV (Earnings Per Visitor) by keyword type:
    - Deal/Coupon: $1.18
    - Comparison:  $0.53
    - Review:      $0.31
    - Best-of:     $0.16

    Capture Rate by view pattern:
    - Distributed:     15%
    - Top Heavy:        8%
    - Winner Take All:  3%
    """
    epv = EPV_BY_TYPE[keyword_type]
    capture_rate = CAPTURE_RATES[view_pattern]
    niche_mult = NICHE_MULTIPLIERS.get(niche, 1.0)

    # Estimate monthly traffic from avg views
    monthly_traffic = avg_views * 3 * capture_rate

    return monthly_traffic * epv * niche_mult
```

### 6.4 Niche Detection
```python
NICHE_PATTERNS = {
    'vpn': {
        'brands': ['nordvpn', 'expressvpn', 'surfshark', 'cyberghost'],
        'terms': ['vpn', 'virtual private network']
    },
    'mattress': {
        'brands': ['purple', 'casper', 'nectar', 'saatva'],
        'terms': ['mattress', 'bed', 'sleep']
    },
    # ... more niches
}

def detect_niche(text):
    text_lower = text.lower()
    for niche, patterns in NICHE_PATTERNS.items():
        if any(brand in text_lower for brand in patterns['brands']):
            return niche
        if any(term in text_lower for term in patterns['terms']):
            return niche
    return 'other'
```

---

## 7. Frontend Components

### 7.1 Tab Structure
```
├── Research Tab
│   ├── Seed Keyword Research Form
│   └── Channel Keyword Analysis
│       ├── Channel Input Form
│       ├── Stats Grid (videos, keywords, hot count)
│       ├── Keywords Table (sortable, selectable)
│       ├── Hot Keywords Grid
│       ├── Republish Analysis
│       └── Videos Table
│
├── Keyword Library Tab
│   ├── Stats Cards
│   ├── Filters (search, niche, tier, label)
│   └── Keywords Table (sortable, bulk actions)
│
├── Domination Score Tab
│   └── Coverage metrics and gaps
│
├── Content Planner Tab
│   └── Prioritized keyword list
│
└── Analytics Tab
    └── Revenue model explanation
```

### 7.2 Key UI Patterns
- **Sortable Tables**: Click header to sort, click again to reverse
- **Badge System**: Color-coded badges for niche, type, tier
- **Hot Indicators**: 🔥 emoji + orange highlighting for trending keywords
- **Add to Library**: Checkbox selection + bulk add buttons

---

## 8. Development Phases

### Phase 1: Foundation (Week 1)
- [ ] Set up Flask project structure
- [ ] Create SQLite database and schema
- [ ] Implement user authentication (Google OAuth)
- [ ] Build basic keyword library CRUD
- [ ] Create responsive dark-theme UI shell

### Phase 2: YouTube Integration (Week 2)
- [ ] Integrate YouTube Data API
- [ ] Build channel video fetcher (playlistItems + videos.list)
- [ ] Implement keyword extraction algorithm
- [ ] Add niche detection
- [ ] Add keyword type classification

### Phase 3: Channel Analysis (Week 3)
- [ ] Build channel analysis endpoint
- [ ] Calculate view distribution patterns
- [ ] Implement republish tracking
- [ ] Add hot keywords detection
- [ ] Create channel analysis UI with sortable table

### Phase 4: Revenue & Scoring (Week 4)
- [ ] Implement revenue estimation model
- [ ] Add conversion immediacy scoring
- [ ] Build opportunity tier calculation
- [ ] Create domination score metrics
- [ ] Add "Add to Library" functionality

### Phase 5: SEO Integration (Week 5)
- [ ] Integrate DataForSEO or similar
- [ ] Add search volume lookups
- [ ] Add keyword difficulty scores
- [ ] Implement related keyword discovery

### Phase 6: Polish & Deploy (Week 6)
- [ ] Add export functionality (CSV)
- [ ] Implement content planner
- [ ] Performance optimization
- [ ] Error handling and logging
- [ ] Deploy to Railway

---

## 9. Environment Variables

```bash
# Required
SERPAPI_API_KEY=xxx          # For YouTube search fallback
YOUTUBE_API_KEY=xxx          # For channel video fetching
DATAFORSEO_LOGIN=xxx         # For search volume (optional)
DATAFORSEO_PASSWORD=xxx

# Authentication
GOOGLE_CLIENT_ID=xxx         # Google OAuth
GOOGLE_CLIENT_SECRET=xxx
SECRET_KEY=xxx               # Flask session key

# Optional
DATABASE_URL=sqlite:///keywords.db
```

---

## 10. File Structure

```
keyword-dashboard/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── keywords.db           # SQLite database
├── templates/
│   └── index.html        # Single-page application
├── static/               # (optional) Static assets
├── .env                  # Environment variables
└── PROJECT_SPEC.md       # This document
```

---

## 11. Key Learnings & Gotchas

### 11.1 YouTube API Limitations
- `playlistItems.list` does NOT return view counts
- Must make separate `videos.list` call with `part=statistics`
- Batch video IDs (max 50 per request) to minimize quota usage
- Channel uploads playlist ID = "UU" + channel_id[2:]

### 11.2 Keyword Extraction Challenges
- Titles use various separators: | - : — –
- Years appear in different formats: 2024, (2024), [2024]
- "Top 10" vs "Best" normalization needed
- Brand names have inconsistent casing

### 11.3 Revenue Estimation
- Search volume ideal but expensive to fetch
- Avg views is reasonable proxy for traffic potential
- EPV varies significantly by keyword type (10x between deal and best-of)
- Niche multipliers matter (VPN converts 1.5x better than general)

### 11.4 Performance Considerations
- Fetching 500+ videos can take 30-60 seconds
- View count fetching adds ~10 seconds per 500 videos
- Consider caching channel analysis results
- Use loading indicators for long operations

---

## 12. Future Enhancements

1. **Scheduled Monitoring**: Auto-refresh channel data weekly
2. **Multi-channel Comparison**: Compare strategies across channels
3. **Trend Detection**: Identify emerging keywords
4. **AI Title Generator**: Suggest titles for target keywords
5. **YouTube Rank Tracking**: Monitor rankings over time
6. **Revenue Import**: Sync actual affiliate revenue data
7. **Team Collaboration**: Multi-user support with roles

---

*Document Version: 1.0*
*Last Updated: February 2026*
