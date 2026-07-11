"""Watch GitHub + X/Twitter for Octra HFHE challenge intel; alert via Telegram state diffs."""

from __future__ import annotations

from datetime import datetime, timezone
from http.client import RemoteDisconnected
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus, urlencode
from urllib.request import Request, urlopen

from .sources import ReconError
from .workspace import write_json

# --- GitHub ---

GITHUB_REPOS: tuple[tuple[str, str], ...] = (
    ("octra-labs", "hfhe-challenge"),
    ("octra-labs", "pvac_hfhe_cpp"),
    ("octra-labs", "wallet-gen"),
    ("octra-labs", "lite_node"),
    ("smoke-ui", "octra-hfhe-v2-security-assessment"),
    ("nftboy07", "octra"),
    ("Iamknownasfesal", "octra-hfhe-challenge-recovery"),  # v1 recovery writeup (historical)
)

GITHUB_SEARCH_QUERIES = (
    "octra HFHE",
    "hfhe-challenge",
    "lpn_samples octra",
    "octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ",
    "pvac_hfhe",
    "R_com octra",
    "FURY octra HFHE",
)

COMMIT_KEYWORDS = (
    "lpn",
    "rku",
    "sample",
    "sk.bin",
    "prf",
    "bounty",
    "secret",
    "mask",
    "recrypt",
    "mnemonic",
    "wallet",
    "break",
    "recover",
    "solve",
    "plaintext",
)

# --- X / Twitter ---

X_ACCOUNTS = (
    "octra",
    "lambda0xE",
    "octralabs",
    "smoke_ui",  # if exists; harmless if not
)

X_SEARCH_QUERIES = (
    "HFHE challenge",
    "octra bounty",
    "octra HFHE",
    "lpn_samples",
    "octC5eR9",
    "hfhe-challenge",
    "pvac_hfhe",
    "from:octra HFHE OR bounty OR LPN OR challenge",
    "from:lambda0xE HFHE OR LPN OR challenge OR sample",
)

INTEL_KEYWORDS = (
    "mnemonic",
    "seed",
    "private key",
    "privkey",
    "solved",
    "recovered",
    "plaintext",
    "rku",
    "prf_k",
    "lpn",
    "secret.ct",
    "bounty",
    "broke",
    "break",
    "writeup",
    "poc",
    "exploit",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _http_json(url: str, headers: dict[str, str] | None = None, timeout: float = 25.0) -> Any:
    hdrs = {
        "Accept": "application/json",
        "User-Agent": "octra-recon-social-watch/1.0",
    }
    if headers:
        hdrs.update(headers)
    req = Request(url, headers=hdrs)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, RemoteDisconnected, ConnectionResetError, OSError) as error:
        raise URLError(str(error)) from error


def _http_text(url: str, headers: dict[str, str] | None = None, timeout: float = 25.0) -> str:
    hdrs = {"User-Agent": "octra-recon-social-watch/1.0"}
    if headers:
        hdrs.update(headers)
    req = Request(url, headers=hdrs)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, RemoteDisconnected, ConnectionResetError, OSError) as error:
        raise URLError(str(error)) from error


def _gh_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "octra-recon-social-watch/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("OCTRA_GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _priority_for_text(text: str) -> str:
    lower = text.lower()
    critical_kw = ("mnemonic", "seed phrase", "private key", "privkey", "recovered", "solved", "plaintext", "rku", "prf_k", "sk.bin")
    high_kw = ("lpn", "writeup", "poc", "break", "bounty", "secret.ct", "sample")
    if any(k in lower for k in critical_kw):
        return "critical"
    if any(k in lower for k in high_kw):
        return "high"
    return "normal"


# ---------- GitHub watchers ----------


def watch_github_repos(state: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Commits + latest issue/PR activity for tracked repos."""
    alerts: list[dict[str, Any]] = []
    shas: dict[str, str] = dict(state.get("shas") or {})
    issue_ids: dict[str, int] = dict(state.get("issue_ids") or {})

    for owner, repo in GITHUB_REPOS:
        key = f"{owner}/{repo}"
        # commits
        try:
            commits = _http_json(
                f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=8",
                headers=_gh_headers(),
            )
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            alerts.append({"source": "github", "repo": key, "error": type(error).__name__, "priority": "info"})
            continue

        if not isinstance(commits, list) or not commits:
            continue
        latest = commits[0].get("sha", "")
        prev = shas.get(key)
        shas[key] = latest
        if prev and prev != latest:
            for commit in commits:
                sha = commit.get("sha", "")
                if sha == prev:
                    break
                msg = ((commit.get("commit") or {}).get("message") or "").split("\n")[0]
                kw = [k for k in COMMIT_KEYWORDS if k.lower() in msg.lower()]
                alerts.append(
                    {
                        "source": "github_commit",
                        "repo": key,
                        "sha": sha[:10],
                        "message": msg[:180],
                        "keywords": kw,
                        "url": commit.get("html_url") or f"https://github.com/{key}/commit/{sha}",
                        "priority": "high" if kw else "normal",
                    }
                )

        # issues (includes PRs in some endpoints; use issues?state=all)
        try:
            issues = _http_json(
                f"https://api.github.com/repos/{owner}/{repo}/issues?state=all&per_page=5&sort=updated",
                headers=_gh_headers(),
            )
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            continue
        if not isinstance(issues, list):
            continue
        max_seen = int(issue_ids.get(key) or 0)
        newest = max_seen
        for issue in issues:
            num = int(issue.get("number") or 0)
            newest = max(newest, num)
            if max_seen and num > max_seen:
                title = issue.get("title") or ""
                body = (issue.get("body") or "")[:200]
                is_pr = "pull_request" in issue
                text = f"{title} {body}"
                alerts.append(
                    {
                        "source": "github_issue" if not is_pr else "github_pr",
                        "repo": key,
                        "number": num,
                        "title": title[:160],
                        "url": issue.get("html_url") or "",
                        "priority": _priority_for_text(text),
                    }
                )
        issue_ids[key] = newest if newest else max_seen

    new_state = {"shas": shas, "issue_ids": issue_ids}
    return alerts, new_state


def watch_github_search(state: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Search new public code/issues matching challenge keywords."""
    alerts: list[dict[str, Any]] = []
    seen: set[str] = set(state.get("search_ids") or [])
    new_seen = set(seen)

    # code search is secondary; issues search is richer for writeups
    for q in GITHUB_SEARCH_QUERIES:
        url = "https://api.github.com/search/issues?" + urlencode(
            {"q": q, "sort": "updated", "order": "desc", "per_page": "5"}
        )
        try:
            payload = _http_json(url, headers=_gh_headers())
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            # rate limit common without token
            if isinstance(error, HTTPError) and error.code == 403:
                alerts.append(
                    {
                        "source": "github_search",
                        "error": "rate_limited",
                        "hint": "Set GITHUB_TOKEN or OCTRA_GITHUB_TOKEN for higher limits",
                        "priority": "info",
                    }
                )
                break
            continue
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            continue
        for item in items:
            item_id = str(item.get("id") or item.get("html_url") or "")
            if not item_id or item_id in seen:
                continue
            new_seen.add(item_id)
            # only alert if first-seen after baseline (if seen empty, seed without flood)
            title = item.get("title") or ""
            repo = ((item.get("repository_url") or "").split("/")[-2:])
            repo_s = "/".join(repo) if len(repo) == 2 else ""
            if seen:  # baseline established
                alerts.append(
                    {
                        "source": "github_search",
                        "query": q,
                        "title": title[:160],
                        "repo": repo_s,
                        "url": item.get("html_url") or "",
                        "priority": _priority_for_text(title + " " + (item.get("body") or "")[:200]),
                    }
                )

    # seed baseline silently
    if not seen:
        new_seen = new_seen  # keep all current as baseline
        alerts = [a for a in alerts if a.get("error")]  # only keep rate-limit info

    return alerts, {"search_ids": sorted(new_seen)[-500:]}


# ---------- X / Twitter ----------


def _x_bearer() -> str | None:
    return (
        os.environ.get("TWITTER_BEARER_TOKEN")
        or os.environ.get("X_BEARER_TOKEN")
        or os.environ.get("OCTRA_X_BEARER_TOKEN")
    )


def watch_x_api(state: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """Twitter API v2 recent search (requires bearer token)."""
    token = _x_bearer()
    if not token:
        return [], state, "no_bearer_token"

    alerts: list[dict[str, Any]] = []
    seen: set[str] = set(state.get("tweet_ids") or [])
    new_seen = set(seen)
    headers = {"Authorization": f"Bearer {token}"}

    queries = list(X_SEARCH_QUERIES)
    for acct in X_ACCOUNTS:
        queries.append(f"from:{acct}")

    for q in queries:
        # recent search
        url = "https://api.twitter.com/2/tweets/search/recent?" + urlencode(
            {
                "query": q + " -is:retweet",
                "max_results": "10",
                "tweet.fields": "created_at,author_id,text",
            }
        )
        try:
            payload = _http_json(url, headers=headers)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            code = getattr(error, "code", None)
            alerts.append(
                {
                    "source": "x_api",
                    "query": q,
                    "error": f"{type(error).__name__}:{code}",
                    "priority": "info",
                }
            )
            continue
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            continue
        for tw in data:
            tid = str(tw.get("id") or "")
            text = tw.get("text") or ""
            if not tid or tid in seen:
                continue
            new_seen.add(tid)
            if seen:
                alerts.append(
                    {
                        "source": "x_tweet",
                        "id": tid,
                        "text": text[:240],
                        "query": q,
                        "url": f"https://x.com/i/web/status/{tid}",
                        "priority": _priority_for_text(text),
                        "created_at": tw.get("created_at"),
                    }
                )

    mode = "api"
    if not seen:
        # baseline: do not flood
        alerts = [a for a in alerts if a.get("error")]
    return alerts, {"tweet_ids": sorted(new_seen)[-800:]}, mode


def watch_x_nitter_rss(state: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """
    Best-effort public RSS via Nitter-style endpoints (instances change often).
    Used only when no X bearer token is configured.
    """
    instances = [
        os.environ.get("OCTRA_NITTER_INSTANCE", "").rstrip("/"),
        "https://nitter.poast.org",
        "https://nitter.net",
    ]
    instances = [i for i in instances if i]

    alerts: list[dict[str, Any]] = []
    seen: set[str] = set(state.get("rss_ids") or [])
    new_seen = set(seen)
    working = None

    paths = [f"/{acct}/rss" for acct in ("octra", "lambda0xE")]
    # search RSS (if supported)
    for q in ("HFHE%20octra", "octra%20bounty"):
        paths.append(f"/search/rss?f=tweets&q={q}")

    for base in instances:
        ok_any = False
        for path in paths:
            url = base + path
            try:
                xml = _http_text(url, timeout=15.0)
            except (HTTPError, URLError, TimeoutError):
                continue
            if "<item>" not in xml and "<entry>" not in xml:
                continue
            ok_any = True
            working = base
            # crude item parse
            items = re.findall(
                r"<item>(.*?)</item>",
                xml,
                flags=re.I | re.S,
            ) or re.findall(r"<entry>(.*?)</entry>", xml, flags=re.I | re.S)
            for block in items[:8]:
                link_m = re.search(r"<link>(.*?)</link>|<link href=\"(.*?)\"", block, re.I)
                title_m = re.search(r"<title[^>]*>(.*?)</title>", block, re.I | re.S)
                guid_m = re.search(r"<guid[^>]*>(.*?)</guid>|<id>(.*?)</id>", block, re.I)
                link = ""
                if link_m:
                    link = (link_m.group(1) or link_m.group(2) or "").strip()
                title = re.sub(r"<[^>]+>", "", (title_m.group(1) if title_m else "")).strip()
                guid = ""
                if guid_m:
                    guid = (guid_m.group(1) or guid_m.group(2) or "").strip()
                item_id = guid or link or title
                if not item_id or item_id in seen:
                    continue
                new_seen.add(item_id)
                if seen:
                    alerts.append(
                        {
                            "source": "x_rss",
                            "title": title[:200],
                            "url": link[:300],
                            "priority": _priority_for_text(title),
                            "instance": base,
                        }
                    )
        if ok_any:
            break

    if not seen:
        alerts = []  # baseline quiet
    mode = f"nitter:{working}" if working else "nitter_unavailable"
    return alerts, {"rss_ids": sorted(new_seen)[-500:]}, mode


def watch_x(state: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    api_state = dict(state.get("x_api") or {})
    rss_state = dict(state.get("x_rss") or {})
    alerts: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}

    a1, s1, mode = watch_x_api(api_state)
    meta["x_mode"] = mode
    if mode == "api":
        alerts.extend(a1)
        return alerts, {"x_api": s1, "x_rss": rss_state, "x_mode": mode}

    # fallback RSS
    a2, s2, mode2 = watch_x_nitter_rss(rss_state)
    meta["x_mode"] = mode2
    alerts.extend(a2)
    if mode == "no_bearer_token":
        alerts.append(
            {
                "source": "x_config",
                "priority": "info",
                "message": (
                    "X API bearer not set; using public RSS fallback if available. "
                    "For reliable tracking set OCTRA_X_BEARER_TOKEN or TWITTER_BEARER_TOKEN."
                ),
            }
        )
    return alerts, {"x_api": s1, "x_rss": s2, "x_mode": mode2, **meta}


# ---------- orchestrate ----------


def social_watch(workspace: Path) -> dict[str, Any]:
    """Full social intel pass; writes state + report; returns alerts for Telegram."""
    state_path = workspace / "logs" / "social_watch_state.json"
    state = _load_state(state_path)

    gh_alerts, gh_repo_state = watch_github_repos(state)
    search_alerts, search_state = watch_github_search(state)
    x_alerts, x_state = watch_x(state)

    # merge state
    new_state = {
        "checked_at": _now(),
        **gh_repo_state,
        **search_state,
        **x_state,
    }
    write_json(state_path, new_state)

    all_alerts = gh_alerts + search_alerts + x_alerts
    # de-prioritize pure info config noise after first run
    actionable = [a for a in all_alerts if a.get("priority") in ("critical", "high", "normal") and not a.get("error")]
    critical = [a for a in actionable if a.get("priority") == "critical"]
    high = [a for a in actionable if a.get("priority") == "high"]

    report = {
        "checked_at": _now(),
        "alert_count": len(actionable),
        "critical_count": len(critical),
        "high_count": len(high),
        "x_mode": new_state.get("x_mode"),
        "alerts": all_alerts[:80],
        "actionable": actionable[:40],
        "critical": critical,
        "high": high,
        "tracked_github_repos": [f"{o}/{r}" for o, r in GITHUB_REPOS],
        "tracked_x_accounts": list(X_ACCOUNTS),
        "note": (
            "Baselines first run silently (no flood). Later new items alert. "
            "Optional: GITHUB_TOKEN, OCTRA_X_BEARER_TOKEN for better coverage."
        ),
    }
    write_json(workspace / "logs" / "social_watch.json", report)
    return report


def social_telegram_messages(report: dict[str, Any], max_messages: int = 6) -> list[str]:
    """Build short TG messages from actionable alerts (critical/high first)."""
    messages: list[str] = []
    ordered = list(report.get("critical") or []) + list(report.get("high") or [])
    # fill with normal if room
    if len(ordered) < max_messages:
        for a in report.get("actionable") or []:
            if a in ordered:
                continue
            ordered.append(a)
            if len(ordered) >= max_messages:
                break

    for a in ordered[:max_messages]:
        src = a.get("source", "?")
        pri = (a.get("priority") or "normal").upper()
        if src.startswith("github"):
            msg = (
                f"GH[{pri}] {a.get('repo', '')} "
                f"{a.get('sha') or a.get('number') or ''} "
                f"{a.get('message') or a.get('title') or ''} "
                f"{a.get('url') or ''}"
            )
        elif src.startswith("x"):
            msg = f"X[{pri}] {a.get('text') or a.get('title') or ''} {a.get('url') or ''}"
        else:
            msg = f"INTEL[{pri}] {json.dumps(a, ensure_ascii=True)[:200]}"
        messages.append(" ".join(msg.split())[:900])

    if not messages and report.get("alert_count") == 0:
        # quiet by default — heartbeat handles liveness
        return []
    return messages
