"""Riga di comando di NarrativeScope."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import networkx as nx

from . import __version__, adstxt, certs, known
from .extract import extract
from .fetch import FetchRefused, PoliteFetcher
from .gdelt import Article, domain_of, search
from .graph import (STRENGTH_ORDER, add_ads_edges, add_articles, add_cert_edges, add_cert_timeline, add_dns_edges,
                    add_known,
                    add_link_edges, add_similarity_edges, export, filter_graph, summary)

log = logging.getLogger("narrativescope")
EDGE_KINDS = ["links_to", "similar_text", "resolves_to", "ads_direct", "ads_owner", "shared_certificate",
              "documented_in"]


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
        description="Grafo OSINT delle relazioni osservabili tra siti e articoli: link, testi simili, "
                    "DNS, ads.txt, certificati TLS e fonti documentali. Ogni arco riporta l'evidenza.",
    )
    src = p.add_argument_group("sorgenti (almeno una)")
    src.add_argument("--query", help="ricerca su GDELT DOC 2.0 (sintassi GDELT)")
    src.add_argument("--urls", type=Path, help="file di testo con un URL per riga")
    src.add_argument("--known", type=Path, help="CSV di domini documentati: domain,source[,url,date,note]")

    g = p.add_argument_group("GDELT")
    g.add_argument("--max-results", type=int, default=50, help="massimo articoli (1-250)")
    g.add_argument("--timespan", default="7d", help="finestra mobile, es. 24h, 7d, 3m")
    g.add_argument("--since", help="data di inizio AAAA-MM-GG (sostituisce --timespan)")
    g.add_argument("--until", help="data di fine AAAA-MM-GG")

    s = p.add_argument_group("segnali")
    s.add_argument("--no-fetch", action="store_true", help="non scaricare le pagine (niente link né testi)")
    s.add_argument("--no-dns", action="store_true", help="non risolvere i domini")
    s.add_argument("--ads", action="store_true", help="leggi ads.txt: account DIRECT e OWNERDOMAIN condivisi")
    s.add_argument("--certs", action="store_true", help="storico certificati da crt.sh (lento)")
    s.add_argument("--threshold", type=float, default=0.6, help="soglia di similarità coseno (0-1)")

    f = p.add_argument_group("filtri e output")
    f.add_argument("--min-strength", choices=list(STRENGTH_ORDER), default="weak",
                   help="scarta gli archi più deboli di questa soglia")
    f.add_argument("--edge-kinds", help=f"tipi di arco da tenere, separati da virgola: {','.join(EDGE_KINDS)}")
    f.add_argument("--no-html", action="store_true", help="non generare graph.html")
    f.add_argument("--output", type=Path, default=Path("output"), help="cartella di output")

    n = p.add_argument_group("rete")
    n.add_argument("--delay", type=float, default=1.5, help="secondi minimi tra richieste allo stesso host")
    n.add_argument("--max-bytes", type=int, default=2_000_000, help="dimensione massima di una risposta")
    n.add_argument("--ignore-robots", action="store_true", help="non leggere robots.txt")

    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def run(args: argparse.Namespace) -> int:
    articles: list[Article] = []
    if args.query:
        log.info("Ricerca GDELT: %s", args.query)
        articles += search(args.query, max_results=args.max_results, timespan=args.timespan,
                            since=args.since, until=args.until)
    if args.urls:
        articles += load_url_file(args.urls)
    known_rows = known.load(args.known) if args.known else []
    if not articles and not known_rows:
        log.warning("Nessun articolo né dominio da analizzare.")
        return 1

    fetcher = PoliteFetcher(delay=args.delay, max_bytes=args.max_bytes, respect_robots=not args.ignore_robots)
    if articles and not args.no_fetch:
        for i, art in enumerate(articles, 1):
            try:
                res = fetcher.get(art.url)
                title, art.text, art.outlinks = extract(res.text, res.final_url)
                art.title = art.title or title
                log.info("[%d/%d] ok %s", i, len(articles), art.url)
            except Exception as exc:  # una pagina irraggiungibile non ferma l'analisi
                art.fetch_error = str(exc)[:200]
                log.info("[%d/%d] saltato %s: %s", i, len(articles), art.url, art.fetch_error)

    g = nx.DiGraph()
    add_articles(g, articles)
    add_known(g, known_rows)
    domains = {n for n, d in g.nodes(data=True) if d.get("kind") == "domain"}
    log.info("Articoli: %d, domini: %d", len(articles), len(domains))

    add_link_edges(g, articles)
    add_similarity_edges(g, articles, threshold=args.threshold)
    if not args.no_dns:
        add_dns_edges(g, domains)
    if args.ads:
        log.info("Lettura ads.txt su %d domini", len(domains))
        add_ads_edges(g, [adstxt.fetch(fetcher, d) for d in sorted(domains)])
    if args.certs:
        log.info("Interrogazione crt.sh su %d domini", len(domains))
        found = {}
        for d in sorted(domains):
            found[d] = certs.lookup(d)
            log.info("  %s: %d certificati", d, len(found[d]))
        add_cert_timeline(g, found)
        add_cert_edges(g, certs.shared_certificates(found, domains))

    kinds = {k.strip() for k in args.edge_kinds.split(",")} if args.edge_kinds else None
    g = filter_graph(g, args.min_strength, kinds)
    paths = export(g, args.output, html=not args.no_html)

    for kind, count in sorted(summary(g).items()):
        log.info("  %-20s %d", kind, count)
    for name, path in paths.items():
        log.info("%s -> %s", name, path)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.query or args.urls or args.known):
        parser.error("serve almeno una sorgente: --query, --urls o --known")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    try:
        return run(args)
    except FetchRefused as exc:
        log.error("Richiesta rifiutata: %s", exc)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
