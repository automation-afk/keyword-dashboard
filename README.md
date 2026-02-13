# Affiliate Keyword Research Dashboard

Interactive dashboard for exploring 1,819 high-intent affiliate keywords with YouTube opportunity validation.

## Features

- **Filter by niche, funnel stage, YouTube pattern, opportunity tier**
- **Sort by any column** (priority, revenue, YT views, etc.)
- **Export filtered results** as CSV
- **Responsive design** works on desktop and mobile

## Deploy to Railway

1. Push this folder to a new GitHub repository
2. Go to [railway.app](https://railway.app) and sign in
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your repository
5. Railway will auto-detect the Python app and deploy
6. Click "Generate Domain" to get your public URL

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py

# Open http://localhost:5000
```

## Data

The keyword data is stored in `data/keywords.csv` with 27 columns including:

- Keyword, niche, funnel stage
- Revenue potential, commission
- YouTube monthly views, view pattern
- Priority score, opportunity tier
- Content angles and rationale

## Tech Stack

- **Backend:** Flask (Python)
- **Frontend:** Vanilla HTML/CSS/JS
- **Deployment:** Railway with Gunicorn

---

Built with Claude
