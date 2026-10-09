#!/usr/bin/env python3
"""Intraday signal row for the statusline: "⚡ CATALYST │ ⚠ MACRO │ BIAS CONF%".

  signal-bar.py fetch   refresh stale sections of the cache (run detached)
  signal-bar.py render  print the row from the cache (statusline hot path)

Code computes (prices, ages, countdowns, catalyst tags, bias, confidence);
the LLM only classifies watchlist headlines the keyword rules cannot tag.
Stdlib only; run with python3 -I. Config: ~/.claude/signal-bar.json.
"""

import json
import os
import re
import sys
import time
from datetime import datetime
from zoneinfo import ZoneInfo

CLAUDE_DIR = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
CONFIG = os.path.join(CLAUDE_DIR, "signal-bar.json")
CACHE = os.path.join(CLAUDE_DIR, "signal-bar-cache.json")
LLM_CACHE = os.path.join(CLAUDE_DIR, "signal-llm-cache.json")
WATCHLIST_FILE = os.path.join(CLAUDE_DIR, "watchlist.txt")
ET_TZ = ZoneInfo("America/New_York")
UA = {"User-Agent": "Mozilla/5.0"}

DEFAULTS = {
    "enable": True,
    "watchlist": [],
    "fallback_watchlist": ["SMCI", "INTC", "BMNR", "MU", "MRNA", "BA"],
    "context": ["SPY", "QQQ", "IWM"],
    "market_ttl_s": 60,
    "news_ttl_s": 120,
    "macro_ttl_s": 1800,
    "news_max_age_min": 240,
    "macro_horizon_h": 24,
    "market_stale_s": 600,
    "max_chars": 120,
    "http_timeout_s": 4,
    "llm": {"enable": True, "base_url": "http://zeroclaw-host:4000/v1",
            "model": "fast", "timeout_s": 8, "max_calls": 5,
            "key_file": "~/.claude/signal-bar.key"},
}

# Highest priority first. EARN and GUIDE share a rank (GUIDE wins the tie
# because guidance usually moves price more than the print itself).
CATEGORIES = ["HALT", "FDA", "M&A", "GUIDE", "EARN", "OFFER", "SEC", "CONTRACT", "PT"]
RANK = {"HALT": 0, "FDA": 1, "M&A": 2, "GUIDE": 3, "EARN": 3,
        "OFFER": 4, "SEC": 5, "CONTRACT": 6, "PT": 7}
CAT_RE = [
    ("HALT", r"\bhalt(?:ed|s)?\b|trading pause|\bpaused trading"),
    ("FDA", r"\bFDA\b|\bPDUFA\b|clinical hold|complete response letter|\bEUA\b"),
    ("M&A", r"\bacquir\w*|\bacquisition\b|\bmerger?\b|\btakeover\b|\bbuyout\b|agrees? to buy|\bto buy\b.*\bfor \$"),
    ("GUIDE", r"\bguidance\b|\boutlook\b|\bforecasts?\b"),
    ("EARN", r"\bearnings\b|quarterly (?:results|profit|revenue)|\bQ[1-4]\b.*\b(?:results|revenue|EPS|profit)\b|\bEPS\b"),
    ("OFFER", r"\boffering\b|share sale|\bdilut\w*|private placement|\bATM\b"),
    ("SEC", r"\bSEC\b|\bsubpoena\b|\bDOJ\b|\bprobe\b|\binvestigation\b|\bdelist\w*"),
    ("CONTRACT", r"\bcontract\b|\bawarded\b|\bwins?\b.*\border\b|\bsupply deal\b"),
    ("PT", r"price target|\bupgrade[sd]?\b|\bdowngrade[sd]?\b|\binitiat\w* coverage"),
]
UP_RE = re.compile(r"\b(?:beats?|tops?|raises?|raised|hikes?|approv\w*|upgrade[sd]?|surg\w*|soar\w*|"
                   r"jumps?|rall\w*|wins?|awarded|record|boosts?|lifts?)\b", re.I)
DOWN_RE = re.compile(r"\b(?:miss(?:es|ed)?|cuts?|lowers?|lowered|reject\w*|downgrade[sd]?|plung\w*|"
                     r"tumbl\w*|sinks?|slumps?|falls?|halt\w*|probe|subpoena|offering|dilut\w*|"
                     r"delay\w*|clinical hold|complete response|warns?)\b", re.I)
OPINION_RE = re.compile(r"\?\s*$|stocks? to (?:buy|watch|sell|own)|should you|is it time|"
                        r"here'?s why|what to know|\btop \d+\b|best stocks?|\bcould\b|\bmight\b|"
                        r"\bmotley\b|\bmillionaire|\bforever\b|about to|set to|poised|\bwill\b|what to expect|"
                        r"\bpreview\b|earnings season|ahead of (?:its |the )?(?:earnings|results|report)|\bexpected to\b|\bwatch\b", re.I)

MACRO_MAP = [  # (label, regex on Forex Factory title), priority order
    ("FOMC", r"FOMC|Federal Funds Rate"),
    ("CPI", r"\bCPI\b"),
    ("NFP", r"Non-Farm Employment Change"),
    ("PCE", r"\bPCE\b"),
    ("GDP", r"\bGDP\b"),
    ("ISM", r"\bISM\b"),
    ("FED", r"Fed Chair|Powell"),
]

# Bias marker: a flat coloured dot (colour emoji render inconsistently in a
# statusline). NO_COLOR is honoured at render time by dot().
DOT_COLOR = {"BULL": "\033[32m", "BEAR": "\033[31m",
             "NEUTRAL": "\033[90m", "MIXED": "\033[38;5;178m"}
ICON = {"BULL": "BULL", "BEAR": "BEAR", "NEUTRAL": "NEUT", "MIXED": "MIX"}


def dot(kind):
    """Coloured ● for a bias kind; the plain glyph when NO_COLOR is set."""
    if os.environ.get("NO_COLOR"):
        return "●"
    return f"{DOT_COLOR[kind]}●\033[0m"


# ---------------------------------------------------------------- helpers

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json_atomic(path, data):
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def load_config():
    cfg = dict(DEFAULTS)
    user = load_json(CONFIG, {})
    llm = dict(DEFAULTS["llm"])
    llm.update(user.get("llm") or {})
    cfg.update(user)
    cfg["llm"] = llm
    return cfg


def resolve_watchlist(cfg):
    def norm(seq):
        return [s.strip().upper() for s in seq if s.strip()]
    env = norm(re.split(r"[,\s]+", os.environ.get("HUD_WATCHLIST", "")))
    if env:
        return env
    try:
        with open(WATCHLIST_FILE) as f:
            lines = norm(re.split(r"[,\s]+", re.sub(r"#.*", "", f.read())))
        if lines:
            return lines
    except OSError:
        pass
    return norm(cfg.get("watchlist") or []) or norm(cfg["fallback_watchlist"])


def http_get(url, timeout):
    import urllib.request
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ---------------------------------------------------------------- classify

def classify(title):
    """Keyword tag: (category or None, direction 'up'|'down'|None). Opinion -> (None, None)."""
    if OPINION_RE.search(title):
        return None, None
    cat = next((c for c, rx in CAT_RE if re.search(rx, title, re.I)), None)
    up, down = bool(UP_RE.search(title)), bool(DOWN_RE.search(title))
    direction = "up" if up and not down else "down" if down and not up else None
    if cat == "HALT":
        direction = None
    return cat, direction


def parse_llm_reply(text):
    """Validate an LLM classification. Returns (cat, dir) or None if invalid/non-factual."""
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("factual") is not True:
        return None
    cat = obj.get("category")
    direction = obj.get("direction")
    if cat not in CATEGORIES or direction not in ("up", "down", "none"):
        return None
    return cat, (None if direction == "none" else direction)


# ---------------------------------------------------------------- fetchers

def fetch_quote(sym, timeout):
    url = ("https://query1.finance.yahoo.com/v8/finance/chart/"
           f"{urllib.parse.quote(sym)}?interval=1m&range=1d&includePrePost=true")
    res = json.loads(http_get(url, timeout))["chart"]["result"][0]
    meta = res["meta"]
    prev = meta.get("previousClose") or meta.get("chartPreviousClose")
    last, t = meta.get("regularMarketPrice"), meta.get("regularMarketTime")
    closes = ((res.get("indicators") or {}).get("quote") or [{}])[0].get("close") or []
    for ts, c in zip(reversed(res.get("timestamp") or []), reversed(closes)):
        if c is not None:
            if t is None or ts > t:
                last, t = c, ts
            break
    if not (last and prev):
        raise ValueError("no price")
    return {"last": last, "prev": prev, "pct": (last / prev - 1) * 100, "t": t,
            "name": meta.get("shortName") or meta.get("longName") or ""}


def fetch_market(cfg, watch):
    syms = list(dict.fromkeys(cfg["context"] + ["^VIX", "^TNX"] + watch))
    quotes = {}
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        futs = {ex.submit(fetch_quote, s, cfg["http_timeout_s"]): s for s in syms}
        for f in concurrent.futures.as_completed(futs):
            try:
                quotes[futs[f]] = f.result()
            except Exception:
                pass
    if not any(s in quotes for s in cfg["context"]):
        raise RuntimeError("market fetch failed")
    return {"ts": int(time.time()), "quotes": quotes}


def fetch_rss(sym, timeout):
    url = ("https://feeds.finance.yahoo.com/rss/2.0/headline?"
           f"s={urllib.parse.quote(sym)}&region=US&lang=en-US")
    out = []
    for item in ET.fromstring(http_get(url, timeout)).iter("item"):
        title = " ".join((item.findtext("title") or "").split())
        try:
            t = int(email.utils.parsedate_to_datetime(item.findtext("pubDate")).timestamp())
        except (TypeError, ValueError):
            continue
        if title:
            out.append({"sym": sym, "title": title, "t": t})
    return out


def mentions(title, sym, name):
    if re.search(rf"\b{re.escape(sym)}\b", title):
        return True
    word = re.split(r"[\s,.]+", name.strip())[0] if name else ""
    return len(word) >= 3 and re.search(rf"\b{re.escape(word)}\b", title, re.I) is not None


def llm_classify(cfg, titles, cache):
    llm = cfg["llm"]
    if not llm.get("enable") or not titles:
        return
    try:
        with open(os.path.expanduser(llm["key_file"])) as f:
            key = f.read().strip()
    except OSError:
        return
    prompt = ("Classify this US-equity headline. Reply with JSON only: "
              '{"category": one of ' + json.dumps(CATEGORIES + ["NONE"]) +
              ', "direction": "up"|"down"|"none", "factual": true|false}. '
              "factual=false for opinion, analysis, listicles or recaps. "
              "category=NONE when no listed catalyst applies.\nHeadline: ")
    for title in titles[: llm["max_calls"]]:
        body = json.dumps({"model": llm["model"], "temperature": 0, "max_tokens": 60,
                           "messages": [{"role": "user", "content": prompt + title}]}).encode()
        req = urllib.request.Request(llm["base_url"].rstrip("/") + "/chat/completions", data=body,
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {key}"})
        try:
            with urllib.request.urlopen(req, timeout=llm["timeout_s"]) as r:
                text = json.loads(r.read())["choices"][0]["message"]["content"]
        except Exception:
            return  # endpoint down: stop, retry next cycle (nothing cached)
        parsed = parse_llm_reply(text)
        cache[hashlib.sha1(title.encode()).hexdigest()] = list(parsed) if parsed else None


def fetch_news(cfg, watch, quotes):
    now = time.time()
    max_age = cfg["news_max_age_min"] * 60
    raw = []
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        for f in [ex.submit(fetch_rss, s, cfg["http_timeout_s"]) for s in watch]:
            try:
                raw.extend(f.result())
            except Exception:
                pass
    llm_cache = load_json(LLM_CACHE, {})
    items, pending, seen = [], [], set()
    for it in raw:
        if now - it["t"] > max_age or it["title"] in seen:
            continue
        name = (quotes.get(it["sym"]) or {}).get("name", "")
        if not mentions(it["title"], it["sym"], name):
            continue
        seen.add(it["title"])
        cat, direction = classify(it["title"])
        if cat is None and not OPINION_RE.search(it["title"]):
            h = hashlib.sha1(it["title"].encode()).hexdigest()
            if h not in llm_cache:
                pending.append(it["title"])
            elif llm_cache[h]:
                cat, direction = llm_cache[h]
                it["src"] = "llm"
        if cat:
            items.append({**it, "cat": cat, "dir": direction, "src": it.get("src", "kw")})
    if pending:
        llm_classify(cfg, pending, llm_cache)
        if len(llm_cache) > 500:
            llm_cache = dict(list(llm_cache.items())[-500:])
        write_json_atomic(LLM_CACHE, llm_cache)
    return {"ts": int(now), "items": items}


def fetch_macro(cfg):
    data = json.loads(http_get("https://nfs.faireconomy.media/ff_calendar_thisweek.json",
                               cfg["http_timeout_s"] + 4))
    events = []
    for ev in data:
        if ev.get("country") != "USD" or ev.get("impact") != "High":
            continue
        label = next((lab for lab, rx in MACRO_MAP if re.search(rx, ev.get("title", ""))), None)
        try:
            t = int(datetime.fromisoformat(ev["date"]).timestamp())
        except (KeyError, ValueError):
            continue
        if label and "All Day" not in str(ev.get("time", "")):
            events.append({"label": label, "t": t})
    return {"ts": int(time.time()), "events": events}


def fetch(cfg):
    global concurrent, email, hashlib, urllib, ET
    import concurrent.futures
    import email.utils
    import hashlib
    import urllib.parse
    import urllib.request
    import xml.etree.ElementTree as ET
    cache = load_json(CACHE, {})
    now = time.time()
    watch = resolve_watchlist(cfg)
    tries = cache.setdefault("tries", {})

    def stale(sec, ttl):
        # Due when data is older than ttl; failed attempts back off (macro: 15 min, 429-prone).
        backoff = 900 if sec == "macro" else ttl
        if now - (cache.get(sec) or {}).get("ts", 0) < ttl or now - tries.get(sec, 0) < backoff:
            return False
        tries[sec] = int(now)
        return True
    if stale("market", cfg["market_ttl_s"]):
        try:
            cache["market"] = fetch_market(cfg, watch)
        except Exception:
            pass
    if stale("news", cfg["news_ttl_s"]):
        try:
            cache["news"] = fetch_news(cfg, watch, (cache.get("market") or {}).get("quotes", {}))
        except Exception:
            pass
    if stale("macro", cfg["macro_ttl_s"]):
        try:
            cache["macro"] = fetch_macro(cfg)
        except Exception:
            pass
    cache["watchlist"] = watch
    cache["fetched_at"] = int(now)
    write_json_atomic(CACHE, cache)


# ---------------------------------------------------------------- render

def fmt_age(sec):
    sec = max(0, int(sec))
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m"
    return f"{sec // 3600}h"


def fmt_eta(sec):
    m = max(0, int(sec)) // 60
    return f"{m}m" if m < 60 else f"{m // 60}h{m % 60:02d}m"


ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def visible_cut(row, limit):
    """Truncate to limit visible cells. Colour escapes never count towards the
    limit and are never cut in half: a row longer than limit keeps limit - 1
    visible cells, an ellipsis, and a reset when any escape was copied."""
    if len(ANSI_RE.sub("", row)) <= limit:
        return row
    out, shown, coloured, i = [], 0, False, 0
    while i < len(row):
        esc = ANSI_RE.match(row, i)
        if esc:
            out.append(esc.group(0))
            coloured = True
            i = esc.end()
            continue
        if shown >= limit - 1:
            break
        out.append(row[i])
        shown += 1
        i += 1
    out.append("…")
    if coloured:
        out.append("\033[0m")
    return "".join(out)


def score_sign(value, band):
    return 0 if value is None or abs(value) < band else (1 if value > 0 else -1)


def compute_bias(quotes, catalysts):
    """Code-only bias. Returns (label, conf) or None when no market data."""
    ctx = [quotes.get(s, {}).get("pct") for s in ("SPY", "QQQ", "IWM")]
    if all(v is None for v in ctx):
        return None
    signals = [score_sign(v, 0.15) for v in ctx]
    signals.append(-score_sign(quotes.get("^VIX", {}).get("pct"), 2.0))
    signals.append(-score_sign(quotes.get("^TNX", {}).get("pct"), 1.5))
    net = sum(1 if c.get("dir") == "up" else -1 if c.get("dir") == "down" else 0 for c in catalysts)
    signals.append(score_sign(net, 1))
    pos, neg = signals.count(1), signals.count(-1)
    nonzero, score = pos + neg, pos - neg
    agree = max(pos, neg) / nonzero if nonzero else 0
    conf = max(0, min(95, round(50 + 50 * agree * min(1, abs(score) / 4))))
    if pos >= 2 and neg >= 2:
        return "MIXED", conf
    if nonzero < 3 or abs(score) <= 1:
        return "NEUTRAL", conf
    return ("BULL" if score > 0 else "BEAR"), conf


def render(cache, cfg, now):
    watch = set(cache.get("watchlist") or [])
    max_age = cfg["news_max_age_min"] * 60
    news = cache.get("news") or {}
    cats = [c for c in news.get("items", []) if 0 <= now - c["t"] <= max_age]
    parts = []

    if cats:
        best = min(cats, key=lambda c: (c["sym"] not in watch, RANK.get(c["cat"], 99), -c["t"]))
        arrow = {"up": "↑", "down": "↓"}.get(best.get("dir"), "")
        parts.append(f"⚡ {best['sym']} {best['cat']}{arrow} {fmt_age(now - best['t'])}")

    horizon = cfg["macro_horizon_h"] * 3600
    upcoming = [e for e in (cache.get("macro") or {}).get("events", []) if 0 <= e["t"] - now <= horizon]
    if upcoming:
        ev = min(upcoming, key=lambda e: e["t"])
        hhmm = datetime.fromtimestamp(ev["t"], ET_TZ).strftime("%H:%M")
        parts.append(f"⚠ {ev['label']} {hhmm} {fmt_eta(ev['t'] - now)}")

    if not parts:
        return f"{dot('NEUTRAL')} {ICON['NEUTRAL']} │ No material catalyst"

    market = cache.get("market") or {}
    if now - market.get("ts", 0) <= cfg["market_stale_s"]:
        bias = compute_bias(market.get("quotes", {}), cats)
        if bias:
            parts.append(f"{dot(bias[0])} {ICON[bias[0]]} {bias[1]}%")

    row = " │ ".join(parts)
    return visible_cut(row, cfg["max_chars"])


def main():
    cfg = load_config()
    if not cfg.get("enable"):
        return 0
    mode = sys.argv[1] if len(sys.argv) > 1 else "render"
    if mode == "fetch":
        fetch(cfg)
    elif mode == "render":
        cache = load_json(CACHE, None)
        if cache:
            print(render(cache, cfg, time.time()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
