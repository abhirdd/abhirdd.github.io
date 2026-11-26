import json, os, re, datetime, urllib.parse
from playwright.sync_api import sync_playwright

BASE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE)
CONFIG = os.path.join(BASE, "query_config.json")
REWARDS_FILE = os.path.join(BASE, "rewards.json")
OUT_DIR = os.path.join(REPO_ROOT, "chromium-monitor", "data")

EXTRACT_JS = """rows => rows.map(r => {
  const td = Array.from(r.querySelectorAll('td')).map(c => (c.innerText || '').trim());
  return {
    id: (r.getAttribute('data-row-id') || td[9] || '').trim(),
    priority: td[3] || '', type: td[4] || '', title: td[5] || '',
    assignee: td[6] || '', status: td[7] || '', views: td[8] || '', modified: td[10] || ''
  };
})"""


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_rewards():
    try:
        with open(REWARDS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def extract_reporters(body):
    rep = {}
    try:
        if not body:
            return rep
        if body.startswith(")]}'\n"):
            body = body[5:]
        data = json.loads(body)
        for iss in data[0][6][0]:
            try:
                iid = str(iss[1])
                if len(iss[2]) > 6 and isinstance(iss[2][6], list) and len(iss[2][6]) > 1:
                    rep[iid] = iss[2][6][1] or ""
            except Exception:
                pass
    except Exception:
        pass
    return rep


def fetch_category(page, cat, rewards):
    q = cat.get("query", "")
    url = "https://issues.chromium.org/issues?q=" + urllib.parse.quote(q, safe="")
    issues, total, error = [], None, None
    CAPTURE = {"body": None}

    def cap(resp):
        if "/action/issues/list" in resp.url:
            try:
                CAPTURE["body"] = resp.text()
            except Exception:
                pass

    try:
        page.on("response", cap)
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        rows = 0
        for _ in range(12):
            page.wait_for_timeout(1000)
            rows = page.locator("tbody tr").count()
            if rows > 0:
                break
        found = False
        try:
            body = page.inner_text("body")
            m = re.search(r"(\d[\d,]*)\s*-\s*(\d[\d,]*)\s+of\s+(\d[\d,]+|many)", body)
            if m:
                found = True
                total = None if m.group(3).lower() == "many" else int(m.group(3).replace(",", ""))
        except Exception:
            pass
        if rows > 0:
            issues = page.locator("tbody tr").evaluate_all(EXTRACT_JS)
            issues = issues[:25] if isinstance(issues, list) else []
            reporters = extract_reporters(CAPTURE.get("body"))
            for it in issues:
                it["reporter"] = reporters.get(it["id"], "")
                it["reward"] = rewards.get(it["id"], "")
                it["url"] = "https://issues.chromium.org/issues/%s" % it["id"]
            if not found:
                total = len(issues)
        else:
            total = 0
    except Exception as e:
        error = str(e)
    finally:
        try:
            page.remove_listener("response", cap)
        except Exception:
            pass

    return {
        "id": cat.get("id"), "title": cat.get("title"), "description": cat.get("description"),
        "query": q, "monorail": cat.get("monorail", ""), "url": url,
        "email": cat.get("email"), "total": total, "issues": issues, "error": error, "fetched_at": now(),
    }


def main():
    with open(CONFIG, encoding="utf-8") as f:
        config = json.load(f)
    rewards = load_rewards()
    categories = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-first-run", "--no-default-browser-check", "--no-sandbox"])
        page = browser.new_page()
        for i, cat in enumerate(config, 1):
            r = fetch_category(page, cat, rewards)
            categories[str(cat["id"])] = r
            print("[%d/%d] %s (%d isu)" % (i, len(config), cat.get("title", ""), len(r.get("issues") or [])))
        browser.close()

    summary = {
        "status": "done",
        "progress": len(categories),
        "total": len(config),
        "categories": categories,
        "last_update": now(),
        "error": None,
        "custom": None,
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False)
    with open(os.path.join(OUT_DIR, "config.json"), "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False)
    print("DONE: %d kategori -> summary.json" % len(categories))


if __name__ == "__main__":
    main()