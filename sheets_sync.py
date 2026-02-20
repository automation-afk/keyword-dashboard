"""
Google Sheets auto-sync for KW Command Center.
Pushes priority keywords and domination data to a single sheet tab.
"""
import json
import os
import threading
import time

_spreadsheet = None

SHEET_NAME = "kwResearchToolapp"

PRIORITY_HEADERS = [
    "keyword", "tier", "niche", "priority_score", "search_volume",
    "source", "is_active", "is_primary", "parent_keyword", "created_at"
]

DOMINATION_HEADERS = [
    "keyword", "domination_score", "positions_owned", "search_volume",
    "revenue", "target", "is_ranking"
]

# Debounce: don't sync more than once every 5 seconds
_last_priority_sync = 0
_last_domination_sync = 0
_DEBOUNCE_SECONDS = 5


def _get_spreadsheet():
    """Lazy-init gspread client and open the target spreadsheet."""
    global _spreadsheet
    if _spreadsheet is not None:
        return _spreadsheet

    spreadsheet_id = os.environ.get('GSHEETS_SPREADSHEET_ID', '')
    if not spreadsheet_id:
        print("[SHEETS] WARNING: GSHEETS_SPREADSHEET_ID not set - sync disabled")
        return None

    sa_json = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON', '')
    if not sa_json:
        print("[SHEETS] WARNING: GOOGLE_SERVICE_ACCOUNT_JSON not set - sync disabled")
        return None

    try:
        import gspread
        from google.oauth2.service_account import Credentials

        scopes = [
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive'
        ]

        if sa_json.strip().startswith('{'):
            info = json.loads(sa_json)
            creds = Credentials.from_service_account_info(info, scopes=scopes)
        else:
            creds = Credentials.from_service_account_file(sa_json, scopes=scopes)

        client = gspread.authorize(creds)
        _spreadsheet = client.open_by_key(spreadsheet_id)
        print(f"[SHEETS] Connected to spreadsheet: {_spreadsheet.title}")
        return _spreadsheet
    except Exception as e:
        print(f"[SHEETS] Error initializing: {e}")
        return None


def _sync_priority_keywords_impl(get_db_func, release_db_func):
    """Fetch all priority keywords from DB, write to the Priority Keywords section."""
    try:
        spreadsheet = _get_spreadsheet()
        if not spreadsheet:
            return

        conn = get_db_func()
        c = conn.cursor()
        c.execute("""
            SELECT keyword, tier, niche, priority_score, search_volume,
                   source, is_active, is_primary, parent_keyword, created_at
            FROM priority_keywords
            ORDER BY is_active DESC, priority_score DESC, keyword
        """)
        rows = c.fetchall()
        release_db_func(conn)

        data = [["--- PRIORITY KEYWORDS ---"] + [''] * (len(PRIORITY_HEADERS) - 1)]
        data.append(PRIORITY_HEADERS)
        for r in rows:
            data.append([
                r[0],                          # keyword
                r[1] or '',                    # tier
                r[2] or '',                    # niche
                float(r[3] or 0),              # priority_score
                int(r[4] or 0),                # search_volume
                r[5] or '',                    # source
                bool(r[6]),                    # is_active
                bool(r[7]),                    # is_primary
                r[8] or '',                    # parent_keyword
                str(r[9]) if r[9] else '',     # created_at
            ])

        worksheet = spreadsheet.worksheet(SHEET_NAME)
        worksheet.clear()
        worksheet.update(data, value_input_option='USER_ENTERED')
        print(f"[SHEETS] Priority Keywords synced: {len(rows)} rows")

    except Exception as e:
        print(f"[SHEETS] Error syncing priority keywords: {e}")


def _sync_domination_impl(domination_data):
    """Write domination data below the priority keywords section."""
    try:
        spreadsheet = _get_spreadsheet()
        if not spreadsheet:
            return

        worksheet = spreadsheet.worksheet(SHEET_NAME)

        # Find where priority keywords section ends (find first empty row)
        all_values = worksheet.get_all_values()
        start_row = len(all_values) + 2  # leave a blank row gap

        audit_by_kw = domination_data.get('audit_results_by_keyword', {})
        targets = domination_data.get('targets', {})
        tracking = domination_data.get('tracking', {})

        data = [["--- RANK DOMINATION ---"] + [''] * (len(DOMINATION_HEADERS) - 1)]
        data.append(DOMINATION_HEADERS)
        if tracking and tracking.get('silos'):
            for silo in tracking['silos']:
                for group in silo.get('groups', []):
                    for kw_entry in group.get('keywords', []):
                        keyword = kw_entry['keyword']
                        audit = audit_by_kw.get(keyword, {})
                        target_info = targets.get(keyword, {})

                        data.append([
                            keyword,
                            audit.get('domination_score', 0),
                            ', '.join(str(p) for p in audit.get('positions_owned', [])),
                            audit.get('search_volume', 0),
                            kw_entry.get('revenue', audit.get('_revenue', 0)),
                            target_info.get('target', 100),
                            audit.get('_is_ranking', False),
                        ])

                        for sec in kw_entry.get('secondary', []):
                            sec_audit = audit_by_kw.get(sec, {})
                            sec_target = targets.get(sec, {})
                            data.append([
                                sec,
                                sec_audit.get('domination_score', 0),
                                ', '.join(str(p) for p in sec_audit.get('positions_owned', [])),
                                sec_audit.get('search_volume', 0),
                                sec_audit.get('_revenue', 0),
                                sec_target.get('target', 100),
                                sec_audit.get('_is_ranking', False),
                            ])

        worksheet.update(data, f'A{start_row}', value_input_option='USER_ENTERED')
        print(f"[SHEETS] Rank Domination synced: {len(data) - 2} rows (starting row {start_row})")

    except Exception as e:
        print(f"[SHEETS] Error syncing domination data: {e}")


def sync_priority_keywords(get_db_func, release_db_func):
    """Fire-and-forget: sync priority keywords to Google Sheets in background."""
    global _last_priority_sync
    now = time.time()
    if now - _last_priority_sync < _DEBOUNCE_SECONDS:
        return
    _last_priority_sync = now
    threading.Thread(
        target=_sync_priority_keywords_impl,
        args=(get_db_func, release_db_func),
        daemon=True
    ).start()


def sync_domination(domination_data):
    """Fire-and-forget: sync domination data to Google Sheets in background."""
    global _last_domination_sync
    now = time.time()
    if now - _last_domination_sync < _DEBOUNCE_SECONDS:
        return
    _last_domination_sync = now
    threading.Thread(
        target=_sync_domination_impl,
        args=(domination_data,),
        daemon=True
    ).start()
