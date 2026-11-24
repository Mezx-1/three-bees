"""Look-alike domain watch: catch scam sites when their HTTPS certificate is issued — often before the first victim.

Every public HTTPS certificate is written to Certificate Transparency logs. 3B searches them (via the free
crt.sh service) for domains containing UAE brand names, keeps only domains that are NOT the brand's official
domains, and scores each one with the same offline URL checks used everywhere else. Only the brand keyword is
sent to crt.sh — never user data.

A hit is a lead for an analyst, not a verdict: a company can legitimately own a similar name (e.g. a bank with
the same initials in another country). The analyst decides whether to add it to the shared list.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import WatchHit, utcnow
from . import url_analyzer as ua, url_deep

WATCH_BRANDS = ["adcb", "emiratesnbd", "bankfab", "mashreq", "adib", "rakbank", "tamm", "uaepass", "salik", "adpolice", "dubaipolice",
                "etisalat", "aramex", "emiratespost", "mohre", "dewa", "icp", "rta"]
SHORT_BRANDS = {"icp", "rta", "adib", "tamm", "dewa"}  # need a separator or digits next to them to count (too many innocent matches)


def _search(keyword: str, client: httpx.Client) -> list[dict]:
    """crt.sh is a free community service and is often overloaded (502/503/429): retry with a short back-off."""
    import time

    last: Exception | None = None
    for wait in (0, 3, 8):
        time.sleep(wait)
        try:
            r = client.get("https://crt.sh/", params={"q": f"%{keyword}%", "output": "json", "exclude": "expired"})
            if r.status_code in (429, 502, 503, 504):
                last = httpx.HTTPStatusError(f"crt.sh busy ({r.status_code})", request=r.request, response=r)
                continue
            r.raise_for_status()
            return r.json()
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last = exc
    raise last or RuntimeError("crt.sh unavailable")


def scan(db: Session, brands: list[str] | None = None, *, client: httpx.Client | None = None, max_new: int = 200) -> dict:
    brands = [b for b in (brands or WATCH_BRANDS) if b in WATCH_BRANDS]
    own = client is None
    client = client or httpx.Client(timeout=40.0, headers=url_deep.UA_HEADER)
    found, errors, new = 0, {}, 0
    added: set[str] = set()
    try:
        for brand in brands:
            try:
                certs = _search(brand, client)
            except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                errors[brand] = f"crt.sh unavailable ({exc}) - try again in a few minutes"
                continue
            seen: dict[str, str] = {}
            for c in certs:
                for name in str(c.get("name_value", "")).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if "." not in name or " " in name or brand not in name.replace("-", ""):
                        continue
                    seen.setdefault(name, c.get("not_before") or "")
            for host, not_before in seen.items():
                reg = ua.registered_domain(host)
                if url_deep.is_official(reg, host) or reg in ua.OFFICIAL_DOMAINS.get(brand, []):
                    continue
                if brand in SHORT_BRANDS and not _separated(host, brand):
                    continue
                found += 1
                if host in added or db.scalars(select(WatchHit).where(WatchHit.host == host)).first() or new >= max_new:
                    continue
                f, info = ua.analyze_url(f"https://{host}/")
                f += url_deep.static_findings(info)
                from .risk import combine

                score = combine(f)
                db.add(WatchHit(host=host, registered_domain=reg, brand=brand, cert_not_before=not_before[:19], score=score,
                                reasons=[x.title for x in sorted(f, key=lambda x: -x.weight) if x.weight > 0][:4]))
                added.add(host)
                new += 1
        db.commit()
    finally:
        if own:
            client.close()
    return {"brands": brands, "domains_seen": found, "new_hits": new, "errors": errors,
            "source": "Certificate Transparency logs via crt.sh", "ran_at": datetime.now(timezone.utc).isoformat()}


def _separated(host: str, brand: str) -> bool:
    import re

    return bool(re.search(rf"(^|[.\-\d]){brand}($|[.\-\d])", host))


def ser(h: WatchHit) -> dict:
    return {"id": h.id, "host": h.host, "registered_domain": h.registered_domain, "brand": h.brand, "cert_not_before": h.cert_not_before,
            "score": h.score, "reasons": h.reasons, "status": h.status, "first_seen": h.first_seen.isoformat() if h.first_seen else None}


def set_status(db: Session, h: WatchHit, status: str) -> None:
    h.status = status
    h.reviewed_at = utcnow()
