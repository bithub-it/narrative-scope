"""Riga di comando di NarrativeScope."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import networkx as nx

from . import __version__
from .extract import extract
from .fetch import FetchRefused, PoliteFetcher
from .gdelt import Article, domain_of, search
from .graph import add_articles, add_dns_edges, add_link_edges, add_similarity_edges, export

log = logging.getLogger("narrativescope")


def load_url_file(path: Path) -> list[Article]:
    articles, seen = [], set()
    for line in path.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url or url.startswith("#") or url in seen:
            continue
        seen.add(url)
        articles.append(Article(url=url, domain=domain_of(url), origin="file"))
    return articles


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="narrativescope",
        description="Mappa relazioni osservabili tra articoli e siti: link, testi simili, DNS corrente. "
                    "Non assegna etichette di propaganda e non dimostra coordinamento.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--query", help="ricerca su GDELT DOC 2.0 (sintassi GDELT)")
    src.add_argument("--urls", type=Path, help="file di testo con un URL per riga")
    p.add_argument("--max-results", type=int, default=50, help="massimo articoli da GDELT (1-250)")
    p.add_argument("--timespan", default="7d", help="finestra temporale GDELT, es. 24h, 7d, 3m")
    p.add_argument("--no-fetch", action="store_true", help="non scaricare le pagine: solo metadati")
    p.add_argument("--no-dns", action="store_true", help="non risolvere i domini")
    p.add_argument("--threshold", type=float, default=0.6, help="soglia di similarità coseno (0-1)")
    p.add_argument("--delay", type=float, default=1.5, help="secondi minimi tra richieste allo stesso host")
    p.add_argument("--max-bytes", type=int, default=2_000_000, help="dimensione massima di una pagina")
    p.add_argument("--ignore-robots", action="store_true", help="non leggere robots.txt (sconsigliato)")
    p.add_argument("--no-html", action="store_true", help="non generare graph.html")
    p.add_argument("--output", type=Path, default=Path("output"), help="cartella di output")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def run(args: argparse.Namespace) -> int:
    if args.query:
        log.info("Ricerca GDELT: %s", args.query)
        articles = search(args.query, max_results=args.max_results, timespan=args.timespan)
    else:
        articles = load_url_file(args.urls)
    if not articles:
        log.warning("Nessun articolo trovato.")
        return 1
    log.info("Articoli: %d su %d domini", len(articles), len({a.domain for a in articles}))

    if not args.no_fetch:
        fetcher = PoliteFetcher(delay=args.delay, max_bytes=args.max_bytes, respect_robots=not args.ignore_robots)
        for i, art in enumerate(articles, 1):
            try:
                res = fetcher.get(art.url)
                title, art.text, art.outlinks = extract(res.text, res.final_url)
                art.title = art.title or title
                log.info("[%d/%d] ok %s", i, len(articles), art.url)
            except (FetchRefused, Exception) as exc:  # un errore su una pagina non ferma l'analisi
                art.fetch_error = str(exc)[:200]
                log.info("[%d/%d] saltato %s: %s", i, len(articles), art.url, art.fetch_error)

    g = nx.DiGraph()
    add_articles(g, articles)
    n_links = add_link_edges(g, articles)
    n_sim = add_similarity_edges(g, articles, threshold=args.threshold)
    n_dns = 0 if args.no_dns else add_dns_edges(g, {a.domain for a in articles})
    paths = export(g, args.output, html=not args.no_html)

    log.info("Archi: %d link, %d similarità, %d DNS", n_links, n_sim, n_dns)
    for name, path in paths.items():
        log.info("%s -> %s", name, path)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    try:
        return run(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
