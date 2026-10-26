"""Costruzione del grafo delle relazioni e relativi export.

Ogni arco porta tre attributi:
- kind: tipo di relazione osservata;
- evidence: cosa è stato osservato, in forma leggibile e verificabile;
- strength: quanto pesa come indizio (fact / moderate / weak).

strength NON è un punteggio di propaganda né di affidabilità politica: descrive
solo la forza dell'osservazione rispetto all'ipotesi di un legame tra due nodi.
"""

from __future__ import annotations

import csv
import json
import socket
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .gdelt import Article, domain_of

STRENGTH_NOTE = {
    "fact": "dato osservato direttamente (es. l'articolo è pubblicato su quel dominio)",
    "moderate": "indizio di relazione (citazione esplicita o testo molto simile), non prova di proprietà comune",
    "weak": "segnale debole: infrastruttura condivisa può dipendere da CDN o hosting comune",
}

COLORS = {"domain": "#22d3ee", "article": "#a78bfa", "ip": "#94a3b8"}
EDGE_COLORS = {"published_on": "#475569", "links_to": "#f59e0b", "similar_text": "#ef4444", "resolves_to": "#64748b"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def add_articles(g: nx.DiGraph, articles: list[Article]) -> None:
    for art in articles:
        g.add_node(art.domain, kind="domain", label=art.domain)
        g.add_node(
            art.url,
            kind="article",
            label=(art.title or art.url)[:80],
            title=art.title,
            language=art.language,
            seen=art.seen,
            origin=art.origin,
            fetch_error=art.fetch_error,
        )
        g.add_edge(art.url, art.domain, kind="published_on", strength="fact",
                   evidence=f"URL ospitato su {art.domain}")


def add_link_edges(g: nx.DiGraph, articles: list[Article]) -> int:
    """Link in uscita verso articoli o domini presenti nel corpus."""
    urls = {a.url for a in articles}
    domains = {a.domain for a in articles}
    count = 0
    for art in articles:
        for link in art.outlinks:
            target_domain = domain_of(link)
            if target_domain == art.domain:
                continue  # link interni allo stesso sito: non dicono nulla sulla rete
            if link in urls:
                target = link
            elif target_domain in domains:
                target = target_domain
            else:
                continue
            if g.has_edge(art.url, target) and g[art.url][target]["kind"] == "links_to":
                continue
            g.add_edge(art.url, target, kind="links_to", strength="moderate",
                       evidence=f"la pagina contiene un link a {link}")
            count += 1
    return count


def add_similarity_edges(g: nx.DiGraph, articles: list[Article], threshold: float = 0.6,
                         min_chars: int = 400) -> int:
    """TF-IDF + similarità coseno tra testi della stessa lingua di caratteri.

    Non riconosce la stessa narrazione tradotta in lingue diverse.
    """
    corpus = [a for a in articles if len(a.text) >= min_chars]
    if len(corpus) < 2:
        return 0
    # Con pochi documenti un max_df basso eliminerebbe proprio i termini condivisi.
    max_df = 0.9 if len(corpus) >= 10 else 1.0
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_df=max_df, sublinear_tf=True)
    try:
        matrix = vectorizer.fit_transform([a.text for a in corpus])
    except ValueError:  # vocabolario vuoto
        return 0
    sims = cosine_similarity(matrix)
    count = 0
    for i, j in combinations(range(len(corpus)), 2):
        a, b = corpus[i], corpus[j]
        if a.domain == b.domain:
            continue
        score = float(sims[i, j])
        if score < threshold:
            continue
        strength = "moderate" if score >= 0.8 else "weak"
        g.add_edge(a.url, b.url, kind="similar_text", strength=strength, score=round(score, 3),
                   evidence=f"similarità TF-IDF coseno {score:.2f} (soglia {threshold:.2f}); "
                            "può indicare ripubblicazione o fonte comune, ad esempio la stessa agenzia")
        count += 1
    return count


def add_dns_edges(g: nx.DiGraph, domains: set[str]) -> int:
    """Risoluzione DNS corrente. È una fotografia di oggi, non lo storico."""
    when = _now()
    count = 0
    for domain in sorted(domains):
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            continue
        for ip in sorted({info[4][0] for info in infos}):
            g.add_node(f"ip:{ip}", kind="ip", label=ip)
            g.add_edge(domain, f"ip:{ip}", kind="resolves_to", strength="weak",
                       evidence=f"{domain} risolveva in {ip} il {when}; IP condivisi sono comuni con CDN e hosting")
            count += 1
    return count


def export(g: nx.DiGraph, outdir: Path, html: bool = True) -> dict[str, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {"edges": outdir / "edges.csv", "graph": outdir / "graph.json"}

    with paths["edges"].open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["source", "target", "kind", "strength", "score", "evidence"])
        for s, t, data in g.edges(data=True):
            writer.writerow([s, t, data.get("kind"), data.get("strength"), data.get("score", ""), data.get("evidence")])

    try:
        payload = nx.node_link_data(g, edges="links")
    except TypeError:  # networkx < 3.4
        payload = nx.node_link_data(g)
    payload["meta"] = {"generated": _now(), "strength_legend": STRENGTH_NOTE}
    paths["graph"].write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    if html:
        from pyvis.network import Network

        net = Network(height="900px", width="100%", directed=True, bgcolor="#0b1020", font_color="#e2e8f0",
                      cdn_resources="remote")
        for node, data in g.nodes(data=True):
            kind = data.get("kind", "domain")
            tooltip = "\n".join(f"{k}: {v}" for k, v in data.items() if v)
            net.add_node(node, label=data.get("label", node), title=f"{node}\n{tooltip}",
                         color=COLORS.get(kind, "#cbd5e1"), shape="dot",
                         size=22 if kind == "domain" else 10 if kind == "article" else 8)
        for s, t, data in g.edges(data=True):
            dashed = data.get("strength") == "weak"
            net.add_edge(s, t, title=f"{data.get('kind')} [{data.get('strength')}]\n{data.get('evidence')}",
                         color=EDGE_COLORS.get(data.get("kind"), "#94a3b8"), dashes=dashed)
        net.barnes_hut()
        paths["html"] = outdir / "graph.html"
        paths["html"].write_text(net.generate_html(notebook=False), encoding="utf-8")
    return paths
