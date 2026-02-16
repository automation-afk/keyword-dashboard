# KW Command Center - Deployment Guide

## Architecture Overview

```
Local Code (your machine)
    ↓ git push
GitHub Repos (both kept in sync)
    ├── automation-afk/keyword-dashboard  (your repo)
    └── manyubtd/keyword-dashboard        (Manyu's repo)
                ↓ auto-deploy webhook
        Railway (kwresearcher.up.railway.app)
                ↓ connects to
        Supabase Postgres (ywfwjvzdbbwgsisdpvlf)
```

## Git Remotes

| Remote     | Repo                              | Purpose              |
|------------|-----------------------------------|----------------------|
| `origin`   | automation-afk/keyword-dashboard  | Your backup repo     |
| `manyubtd` | manyubtd/keyword-dashboard        | Triggers Railway deploy |

Check remotes: `git remote -v`

## How to Deploy

Always push to **both** remotes to keep them in sync:

```bash
git add <files>
git commit -m "Your message"
git push origin main
git push manyubtd main
```

Railway auto-deploys when `manyubtd/keyword-dashboard` main branch receives a push.

## Railway Details

- **URL:** https://kwresearcher.up.railway.app
- **Source:** manyubtd/keyword-dashboard → main branch
- **Auto-deploy:** Yes (on push to main)
- **Your access:** Collaborator (cannot reconnect repo or change source settings)

## Environment Variables (Railway)

These are set in Railway's **Variables** tab. Do NOT change unless you know what you're doing.

### Database (CRITICAL - must use pooler URL)

| Variable             | Value |
|----------------------|-------|
| `DATABASE_URL`       | `postgresql://postgres:TyV4viBBvAiZiN7y@db.ywfwjvzdbbwgsisdpvlf.supabase.co:5432/postgres` |
| `DATABASE_POOLER_URL`| `postgresql://postgres.ywfwjvzdbbwgsisdpvlf:TyV4viBBvAiZiN7y@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres` |
| `SUPABASE_URL`       | `https://ywfwjvzdbbwgsisdpvlf.supabase.co` |
| `SUPABASE_KEY`       | (anon key - already set) |

**IMPORTANT:** The pooler URL must use:
- Region: `aws-1-ap-southeast-1` (NOT us-east-1)
- Port: `5432` (NOT 6543)
- Host: `pooler.supabase.com` (NOT db.supabase.co)

Railway cannot connect to Supabase's direct DB (IPv6 unreachable). The app tries the pooler first automatically.

### Authentication

| Variable                    | Purpose                          |
|-----------------------------|----------------------------------|
| `GOOGLE_CLIENT_ID`          | OAuth login                      |
| `GOOGLE_CLIENT_SECRET`      | OAuth login                      |
| `GOOGLE_SERVICE_ACCOUNT_JSON`| Google Search Console access    |
| `APP_URL`                   | Must be `https://kwresearcher.up.railway.app` |
| `ALLOWED_DOMAINS`           | Comma-separated email domains    |

**Google Cloud Console must have this redirect URI:**
```
https://kwresearcher.up.railway.app/auth/callback
```

### API Keys

| Variable                    | Service              |
|-----------------------------|----------------------|
| `AHREFS_API_KEY`            | Ahrefs               |
| `SERPAPI_API_KEY`            | SerpAPI              |
| `KEYWORDS_EVERYWHERE_API_KEY`| Keywords Everywhere |
| `DATAFORSEO_LOGIN`          | DataForSEO           |
| `DATAFORSEO_PASSWORD`       | DataForSEO           |
| `YOUTUBE_API_KEY`           | YouTube Data API     |

### Other

| Variable           | Purpose                        |
|--------------------|--------------------------------|
| `FLASK_SECRET_KEY` | Session encryption             |
| `CRON_SECRET`      | Protects cron endpoints        |

## Common Issues & Fixes

### 1. DB Connection Error (IPv6 / Network Unreachable)

**Symptom:** "connection to server at db.ywfwjvzdbbwgsisdpvlf.supabase.co failed: Network is unreachable"

**Cause:** Railway can't reach Supabase direct DB via IPv6.

**Fix:** Ensure `DATABASE_POOLER_URL` is set correctly (see above). The app tries pooler first.

### 2. Railway Not Auto-Deploying After Push

**Symptom:** Push goes through but Railway shows old deployment.

**Fixes:**
- Check Railway Deployments tab for a new build
- Force push may break the webhook - push a new commit to trigger it
- If source repo is disconnected: Manyu (owner) must reconnect in Settings → Source
- Manual redeploy: Deployments tab → three dots → Redeploy

### 3. Features Missing After Merge

**Symptom:** Keyword Manager, BigQuery, or other features disappeared.

**Cause:** A merge from another branch overwrote your code with a simpler version.

**Fix:**
```bash
# Find the last good commit
git log --oneline -10

# Reset to it
git reset --hard <good-commit-hash>

# Force push to both repos
git push origin main --force
git push manyubtd main --force
```

**Prevention:** Before merging any PR from Manyu's repo, check the diff carefully:
```bash
git diff main...<branch-to-merge> --stat
```
If it shows massive deletions in app.py or index.html, DO NOT merge.

### 4. OAuth Login Not Working

**Symptom:** Login redirects fail or show errors.

**Check:**
- `APP_URL` matches the actual Railway URL
- Redirect URI is added in Google Cloud Console
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set

### 5. App Takes Long to Start

**Normal.** The app loads 20K+ keywords from Supabase on startup. Takes 60-90 seconds. Railway health checks may timeout - this is fine.

## Running Locally

```bash
cd "/Users/jen/Digidom/claude_code/Ai Apps/kw command center tool"

# Kill any existing instance
lsof -ti:5001 | xargs kill -9

# Start the app
PYTHONUNBUFFERED=1 ./venv/bin/python app.py
```

App runs on http://localhost:5001

## Key Files

| File                    | Purpose                          |
|-------------------------|----------------------------------|
| `app.py`                | Flask backend (~8400 lines)      |
| `templates/index.html`  | Frontend UI (~6400 lines)        |
| `supabase_setup.sql`    | Database schema                  |
| `requirements.txt`      | Python dependencies              |
| `Procfile`              | Railway start command            |
| `railway.json`          | Railway build config             |
