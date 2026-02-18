# Google Trends Intelligence — Trend Prediction & Seasonal Patterns

## Overview

The app uses Google Trends data (via SerpAPI) to provide two layers of keyword intelligence:

1. **Trend Prediction** — Is the keyword trending up or down right now?
2. **Seasonal Patterns** — What months does the keyword peak, and when should you publish?

Both use the same 5-year Google Trends dataset — no extra API calls needed.

---

## Trend Prediction

Shows whether a keyword's search interest is **rising**, **stable**, or **declining** compared to the same period last year.

### How It Works

1. Fetches 5 years of weekly interest data from Google Trends
2. Compares the last ~3 months of data against the same period one year ago
3. Calculates the percentage change between the two periods
4. Classifies the trend:

| Change | Direction | Meaning |
|---|---|---|
| > +20% | **Rising** | Growing search interest — opportunity is expanding |
| -20% to +20% | **Stable** | Consistent interest — reliable keyword |
| < -20% | **Declining** | Falling interest — consider timing risk |

### Where It Appears

| Location | What you see |
|---|---|
| **Keyword Library** | "Trend" column — green `Rising`, blue `Stable`, red `Declining` badges with % change |
| **$3K Finder** | "Google Trend" metric on each opportunity card |
| **Smart Picks** | Trend badge next to keyword type and niche |
| **Content Planner** | (via seasonal data — see below) |

### Scoring Impact

| Trend | $3K Finder | Smart Picks |
|---|---|---|
| Rising | +10 pts | +10 pts |
| Stable | +5 pts | +5 pts |
| Unknown | +3 pts | +3 pts |
| Declining | +0 pts | +0 pts |

Declining keywords also get a "timing risk" warning in the $3K Finder levers.

### Fetching Trend Data

- **Individual** — Click "Fetch" button in the Trend column for any keyword
- **Bulk** — Click "Collect Trends" in the admin section (batches of 25)
- **Automatic** — App triggers collection on startup if data is stale
- **Trending Gaps** — The Content Gap tab has "Discover Trending Gaps" to find rising topics you're not covering

---

## Seasonal Patterns — Best Time to Publish

Analyzes the same 5-year data to detect which months each keyword peaks in search interest. This tells you **when** to publish content for maximum impact.

## Key Concepts

| Term | Meaning |
|---|---|
| **Peak Months** | Months where search interest is consistently above average (e.g., Oct, Nov, Dec) |
| **Publish Window** | 1-2 months before peak — the ideal time to create and publish content |
| **Seasonality Score** | 0-100 scale. Higher = more seasonal. Lower = consistent year-round |
| **Evergreen** | Score 30 or below — interest is steady all year, publish anytime |

## How It Works

1. Google Trends returns weekly interest scores (0-100) over 5 years (~260 data points)
2. Data points are grouped by month (Jan-Dec) across all years
3. Monthly averages are calculated to find the typical interest pattern
4. Months with interest >= 115% of overall average are flagged as **peak months**
5. Months with interest <= 85% of average are flagged as **low months**
6. The **seasonality score** is the coefficient of variation across months, scaled to 0-100

## Where It Appears

### Keyword Library — "Season" column

| Badge | Meaning |
|---|---|
| `Publish NOW` (orange) | Current month is in the publish window — peak is approaching |
| `Peak NOW` (green) | Current month is a peak month — content should already be live |
| `Peak: Oct,Nov` (yellow) | Shows peak months. Hover for full details + publish window |
| `Evergreen` (light green) | Low seasonality — publish anytime |
| `—` | No trend data collected yet. Click "Fetch" on the Trend column first |

### Content Planner — "Best Publish" column

Shows the same indicators with additional context:
- **Publish NOW** — with peak months listed below
- **Peak NOW** — content should already be ranking
- **Peak: Oct,Nov / Publish by Aug-Sep** — future timing guidance
- **Evergreen** — no urgency, publish when ready

### $3K Finder — "Season" metric

Each opportunity card shows a Season metric box alongside Google Trend, Buyer Intent, etc.

### Smart Picks — Badge

A small badge appears next to the trend indicator (Rising/Stable/Declining) showing seasonal timing.

## Scoring Impact

Keywords approaching their peak season get a scoring boost:

| Condition | $3K Finder Bonus | Smart Picks Bonus |
|---|---|---|
| Current month is in publish window | +5 points | +5 points |
| Current month is in peak season | +3 points | +3 points |
| No seasonal data or evergreen | +0 points | +0 points |

This means seasonally timely keywords bubble up higher in recommendations.

## Populating Seasonal Data

Seasonal data is collected alongside regular trend data. There are three ways:

1. **Individual fetch** — In the Keyword Library, click the "Fetch" button in the Trend column for any keyword
2. **Bulk collection** — In the Admin section, click "Collect Trends" to process keywords in batches of 25
3. **Automatic** — The app checks on startup and triggers collection if data is stale (< 10% of keywords have fresh data)

Data is cached for 7 days before re-fetching.

## Database Schema

All data is stored in the `keyword_trends` table:

```
-- Trend Prediction fields
trend             TEXT    — "rising", "stable", "declining", or "unknown"
trend_change_pct  FLOAT   — Year-over-year percentage change (e.g., +34.2 or -15.8)
current_interest  INTEGER — Current interest score (0-100)
data_points       INTEGER — Number of data points from Google Trends

-- Seasonal Pattern fields
peak_months       TEXT    — Comma-separated peak months (e.g., "Oct,Nov,Dec")
low_months        TEXT    — Comma-separated low months (e.g., "Mar,Apr")
seasonality_score INTEGER — 0-100, higher = more seasonal
publish_window    TEXT    — Best months to publish (e.g., "Aug-Sep")
monthly_averages  JSONB   — Average interest per month {"Jan": 45.2, "Feb": 38.1, ...}

-- Metadata
updated_at        TIMESTAMP — Last refresh (data re-fetched after 7 days)
```

## Example

**Keyword: "best antivirus"**

```
Peak Months:      Oct, Nov, Dec
Low Months:       May, Jun, Jul
Seasonality Score: 62
Publish Window:    Aug-Sep
```

Interpretation: Search interest spikes in Q4 (holiday shopping season). Publish antivirus content by August-September so it's indexed and ranking before the peak.

**Keyword: "vpn for streaming"**

```
Peak Months:      (none above threshold)
Seasonality Score: 18
Publish Window:    (none)
```

Interpretation: Evergreen keyword — people search for streaming VPNs year-round. Publish whenever ready.
