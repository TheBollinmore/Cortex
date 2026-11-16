"""
ArtexLookupSync  (Cortex XSIAM / XSOAR automation, Python 3)

Keeps a lookup dataset of exposed ARTEX console IPs in sync with a Shodan search, once a day.
Shodan is called directly (api.shodan.io over HTTPS from the script container); the lookup is
read and written through the Core REST API integration (`core-api-post`). No engine required.

Script arguments
  shodan_api_key      Shodan API key (required; mark the argument Secret + Mandatory in the script settings)
  query               Shodan search (default: product:"ARTEX")
  lookup_name         lookup dataset to maintain (default "artex")
  core_api_instance   Core REST API instance name; omit if you have exactly one
  prune               "true" = lookup mirrors today's Shodan results exactly: any IP not returned
                      today is deleted. Default "false".
  retain_days         full-schema mode only: drop rows whose last_seen is older than this (default 90)
  max_pages           Shodan pages to walk, 100 results each (default 40)
  time_budget         seconds to spend paging Shodan before stopping (default 480). A partial fetch is
                      reported as fetch_complete=false and NEVER prunes.
  dry_run             "true" = query Shodan + read the lookup, compute the diff, write nothing

Two modes, chosen automatically from the lookup's columns
  ip-only lookup (single `ip` column)
    - new IPs are added; existing rows are never modified
    - prune=true additionally deletes IPs that Shodan no longer returns
  full-schema lookup (ip, first_seen, last_seen, active, ports, hostnames, org, asn, country, source, query)
    - seen today             -> upsert, active="1", last_seen=today, first_seen preserved
    - not seen, in window    -> kept, active="0"  (infrastructure stays hot after a console goes dark)
    - last_seen > retain_days-> removed
    - rows with no last_seen -> grandfathered: last_seen=today, source="manual", active="0"
    - prune=true overrides all of the above and mirrors Shodan exactly
"""
import json
import time
from datetime import datetime, timedelta, timezone

import requests

SCHEMA = ["ip", "first_seen", "last_seen", "active", "ports", "hostnames", "org", "asn", "country", "source", "query"]
CHUNK = 1000          # lookup API guidance: ~1000 entries per add_data call, ~10 s apart, never concurrent
DEFAULT_QUERY = 'product:"ARTEX"'
SHODAN_URL = "https://api.shodan.io/shodan/host/search"

args = demisto.args()
QUERY = (args.get("query") or DEFAULT_QUERY).strip()
LOOKUP = args.get("lookup_name", "artex")
SHODAN_KEY = (args.get("shodan_api_key") or "").strip()
if not SHODAN_KEY:
    raise DemistoException("shodan_api_key is required")
API_USING = (args.get("core_api_instance") or "").strip()
RETAIN_DAYS = int(args.get("retain_days", 90))
MAX_PAGES = int(args.get("max_pages", 40))
TIME_BUDGET = int(args.get("time_budget", 480))
DRY_RUN = argToBoolean(args.get("dry_run", False))
PRUNE = argToBoolean(args.get("prune", False))

PAGES = []
STATE = {"complete": False}
T0 = time.time()
NOW = datetime.now(timezone.utc)
TODAY = NOW.strftime("%Y-%m-%d")


def core_post(uri, body):
    a = {"uri": uri, "body": json.dumps(body)}
    if API_USING:
        a["using"] = API_USING
    res = demisto.executeCommand("core-api-post", a)
    if is_error(res):
        raise DemistoException(f"{uri}: {get_error(res)}")
    c = res[0].get("Contents")
    if isinstance(c, str):
        try:
            c = json.loads(c)
        except ValueError:
            pass
    if isinstance(c, dict) and "response" in c:
        c = c["response"]
    if isinstance(c, dict) and "reply" in c:
        c = c["reply"]
    return c if isinstance(c, dict) else {}


def shodan_page(query, page):
    """One page (<=100 matches) of GET /shodan/host/search, with retry on 429/5xx."""
    r = None
    for attempt in range(3):
        r = requests.get(SHODAN_URL, params={"key": SHODAN_KEY, "query": query, "page": page}, timeout=90)
        if r.status_code == 200:
            return r.json().get("matches", []) or []
        if r.status_code in (429, 500, 502, 503, 504):
            time.sleep(5 * (attempt + 1))
            continue
        raise DemistoException(f"shodan '{query}' page {page}: HTTP {r.status_code} {r.text[:200]}")
    raise DemistoException(f"shodan '{query}' page {page}: gave up after 3 attempts (HTTP {r.status_code})")


def shodan_search(query):
    """Walk all pages; one entry per IP with ports/hostnames/org/asn/country merged across banners."""
    hits = {}
    for page in range(1, MAX_PAGES + 1):
        if time.time() - T0 > TIME_BUDGET:
            return hits                                   
        matches = [m for m in shodan_page(query, page) if m.get("ip_str")]
        if not matches:
            STATE["complete"] = True                      
            break
        before = len(hits)
        PAGES.append(page)
        for m in matches:
            ip = m["ip_str"]
            h = hits.setdefault(ip, {"ports": set(), "hostnames": set(), "org": "", "asn": "", "country": ""})
            h["ports"].add(str(m.get("port", "")))
            h["hostnames"].update(m.get("hostnames") or [])
            h["org"] = h["org"] or (m.get("org") or "")
            h["asn"] = h["asn"] or (m.get("asn") or "")
            h["country"] = h["country"] or ((m.get("location") or {}).get("country_code") or "")
        if page > 1 and len(hits) == before:
            STATE["complete"] = True                      
            break
        if len(matches) < 100:
            STATE["complete"] = True                     
            break
        time.sleep(1.1)                                   # Shodan rate limit: 1 request/second
    else:
        pass                                              
    return hits


def existing_rows():
    r = core_post("/public_api/v1/xql/lookups/get_data", {"request_data": {"dataset_name": LOOKUP}})
    return {row["ip"]: row for row in (r.get("data") or []) if isinstance(row, dict) and row.get("ip")}


def lookup_columns(current):
    """Columns the lookup actually has, inferred from its rows. Empty lookup -> full schema."""
    if not current:
        return list(SCHEMA)
    present = set()
    for row in current.values():
        present.update(k for k in row.keys() if k in SCHEMA)
    return [c for c in SCHEMA if c in present] or ["ip"]


def main():
    live = shodan_search(QUERY)
    current = existing_rows()
    cols = lookup_columns(current)
    full_schema = "last_seen" in cols
    cutoff = (NOW - timedelta(days=RETAIN_DAYS)).strftime("%Y-%m-%d")

    rows, stale, inactivated = [], [], 0
    for ip, h in live.items():
        prev = current.get(ip, {})
        rows.append({
            "ip": ip,
            "first_seen": prev.get("first_seen") or TODAY,
            "last_seen": TODAY,
            "active": "1",
            "ports": ",".join(sorted(p for p in h["ports"] if p)),
            "hostnames": ",".join(sorted(h["hostnames"]))[:500],
            "org": (h["org"] or "")[:200],
            "asn": h["asn"] or "",
            "country": h["country"] or "",
            "source": "shodan",
            "query": QUERY[:200],
        })

    for ip, prev in current.items():
        if ip in live:
            continue
        if PRUNE:
            if STATE["complete"]:
                stale.append(ip)                            
            continue                                        
        if not full_schema:
            continue                                        
        last_seen = prev.get("last_seen") or TODAY          
        if last_seen < cutoff:
            stale.append(ip)
            continue
        if prev.get("active") == "0" and prev.get("last_seen"):
            continue                                        
        row = {k: (prev.get(k) or "") for k in SCHEMA}      
        row.update({"ip": ip, "last_seen": last_seen, "active": "0",
                    "first_seen": prev.get("first_seen") or last_seen,
                    "source": prev.get("source") or "manual"})
        rows.append(row)
        inactivated += 1

    rows = [{k: v for k, v in r.items() if k in cols} for r in rows]     
    if not full_schema:
        rows = [r for r in rows if r["ip"] not in current]               

    base = {
        "run_date": TODAY, "query": QUERY, "lookup": LOOKUP, "lookup_columns": cols,
        "decay_enabled": full_schema, "prune": PRUNE,
        "shodan_ips": len(live), "pages_fetched": len(PAGES),
        "fetch_complete": STATE["complete"], "elapsed_s": int(time.time() - T0),
    }

    if DRY_RUN:
        summary = {**base, "dry_run": True,
                   "lookup_rows_now": len(current), "would_upsert": len(rows),
                   "would_inactivate": inactivated, "would_delete": len(stale),
                   "new_ips": [ip for ip in live if ip not in current][:50],
                   "stale_ips": stale[:50], "sample_rows": rows[:5]}
        return_results(CommandResults(outputs_prefix="ArtexLookupSync", outputs=summary,
                                      readable_output=tableToMarkdown("ArtexLookupSync (dry run)", summary)))
        return

    added = updated = 0
    for i in range(0, len(rows), CHUNK):
        r = core_post("/public_api/v1/xql/lookups/add_data",
                      {"request_data": {"dataset_name": LOOKUP, "key_fields": ["ip"], "data": rows[i:i + CHUNK]}})
        added += int(r.get("added", 0) or 0)
        updated += int(r.get("updated", 0) or 0)
        if i + CHUNK < len(rows):
            time.sleep(10)

    deleted = 0
    for ip in stale:
        r = core_post("/public_api/v1/xql/lookups/remove_data",
                      {"request_data": {"dataset_name": LOOKUP, "filters": {"ip": ip}}})
        deleted += int(r.get("deleted", 0) or 0)

    summary = {**base, "added": added, "updated": updated, "inactivated": inactivated, "deleted": deleted,
               "lookup_rows_after": len(current) + added - deleted}
    return_results(CommandResults(outputs_prefix="ArtexLookupSync", outputs=summary,
                                  readable_output=tableToMarkdown("ArtexLookupSync", summary)))


main()
