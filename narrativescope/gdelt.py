"""Ricerca articoli tramite l'API pubblica GDELT DOC 2.0 (modalità ArtList).

GDELT restituisce metadati (URL, titolo, dominio, lingua, paese della fonte,
data in cui l'articolo è stato visto), non il testo completo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from .fetch import USER_AGENT

GDELT_DOC_API = "https://api.gdeltproject.org/api/v2/doc/doc"


@dataclass
class Article:
    url: str
    domain: str
    title: str = ""
    language: str = ""
    source_country: str = ""
    seen: str = ""
    origin: str = "gdelt"
    text: str = ""
    outlinks: list[str] = field(default_factory=list)
    fetch_error: str = ""


def domain_of(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _parse_seen(value: str) -> str:
    # GDELT usa il formato 20240212T153000Z
    try:
        return datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return value or ""


def parse_artlist(payload: dict) -> list[Article]:
    articles = []
    for item in payload.get("articles", []) or []:
        url = item.get("url")
        if not url:
            continue
        articles.append(
            Article(
                url=url,
                domain=(item.get("domain") or domain_of(url)).lower().removeprefix("www."),
                title=item.get("title", ""),
                language=item.get("language", ""),
                source_country=item.get("sourcecountry", ""),
                seen=_parse_seen(item.get("seendate", "")),
            )
        )
    return articles


def _gdelt_datetime(value: str, end: bool = False) -> str:
    """Accetta AAAA-MM-GG o AAAA-MM-GGTHH:MM e restituisce il formato GDELT AAAAMMGGHHMMSS."""
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt)
        except ValueError:
            continue
        if fmt == "%Y-%m-%d" and end:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt.strftime("%Y%m%d%H%M%S")
    raise ValueError(f"data non valida: {value} (usa AAAA-MM-GG)")


def build_params(query: str, max_results: int = 50, timespan: str = "7d",
                 since: str | None = None, until: str | None = None) -> dict:
    params = {
        "query": query,
        "mode": "ArtList",
        "format": "json",
        "maxrecords": max(1, min(int(max_results), 250)),
        "sort": "DateDesc",
    }
    if since or until:
        if since:
            params["startdatetime"] = _gdelt_datetime(since)
        if until:
            params["enddatetime"] = _gdelt_datetime(until, end=True)
    else:
        params["timespan"] = timespan
    return params


def search(query: str, max_results: int = 50, timespan: str = "7d", since: str | None = None,
           until: str | None = None, timeout: float = 30.0) -> list[Article]:
    params = build_params(query, max_results, timespan, since, until)
    resp = requests.get(GDELT_DOC_API, params=params, timeout=timeout, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    try:
        payload = resp.json()
    except ValueError as exc:
        # In caso di query non valida GDELT risponde con un messaggio in testo semplice
        raise RuntimeError(f"risposta GDELT non JSON: {resp.text[:200]}") from exc
    return parse_artlist(payload)
