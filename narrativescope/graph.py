"""Costruzione del grafo delle relazioni e relativi export.

Ogni arco porta tre attributi:
- kind: tipo di relazione osservata;
- evidence: cosa è stato osservato, in forma leggibile e verificabile;
- strength: peso dell'osservazione come indizio di legame (fact / moderate / weak).

I segnali "hub" (IP, account pubblicitari, certificati, fonti documentali) sono nodi
a sé: i domini che li condividono si raggruppano attorno allo stesso nodo.
"""

from __future__ import annotations

import csv
import json
import socket
from collections import defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .adstxt import AdsTxt
from .certs import SHARED_CERT_NAMES, Certificate
from .gdelt import Article, domain_of
from .known import KnownDomain

STRENGTH_ORDER = {"weak": 0, "moderate": 1, "fact": 2}
STRENGTH_NOTE = {
    "fact": "dato osservato direttamente o dichiarato da una fonte citata",
    "moderate": "indizio specifico di legame (citazione, testo quasi identico, stesso account o certificato)",
    "weak": "segnale generico: spesso condiviso anche da soggetti indipendenti (IP, certificati CDN)",
}

COLORS = {"domain": "#22d3ee", "article": "#a78bfa", "ip": "#94a3b8", "ads": "#facc15",
          "owner": "#fb923c", "cert": "#4ade80", "source": "#f472b6"}
EDGE_COLORS = {"published_on": "#475569", "links_to": "#f59e0b", "similar_text": "#ef4444",
               "resolves_to": "#64748b", "ads_direct": "#facc15", "ads_owner": "#fb923c",
               "shared_certificate": "#4ade80", "documented_in": "#f472b6"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def add_domain(g: nx.DiGraph, domain: str) -> None:
    if domain not in g:
        g.add_node(domain, kind="domain", label=domain)


def add_articles(g: nx.DiGraph, articles: list[Article]) -> None:
    for art in articles:
        add_domain(g, art.domain)
        g.add_node(art.url, kind="article", label=(art.title or art.url)[:80], title=art.title,
                   language=art.language, seen=art.seen, origin=art.origin, fetch_error=art.fetch_error)
        g.add_edge(art.url, art.domain, kind="published_on", strength="fact",
                   evidence=f"URL ospitato su {art.domain}")


def add_known(g: nx.DiGraph, known: list[KnownDomain]) -> int:
    for item in known:
        add_domain(g, item.domain)
        src = f"source:{item.source}"
        g.add_node(src, kind="source", label=item.source)
        when = f" ({item.date})" if item.date else ""
        g.add_edge(item.domain, src, kind="documented_in", strength="fact", date=item.date,
                   evidence=f"elencato in {item.source}{when}" + (f": {item.url}" if item.url else "")
                            + (f" – {item.note}" if item.note else ""))
        documented = g.nodes[item.domain].setdefault("documented_in", [])
        if item.source not in documented:
            documented.append(item.source)
    return len(known)


def add_link_edges(g: nx.DiGraph, articles: list[Article]) -> int:
    """Link in uscita verso articoli o domini presenti nel grafo."""
    urls = {a.url for a in articles}
    domains = {n for n, d in g.nodes(data=True) if d.get("kind") == "domain"}
    count = 0
    for art in articles:
        for link in art.outlinks:
            target_domain = domain_of(link)
            if target_domain == art.domain:
                continue
            target = link if link in urls else target_domain if target_domain in domains else None
            if target is None or g.has_edge(art.url, target):
                continue
            g.add_edge(art.url, target, kind="links_to", strength="moderate",
                       evidence=f"la pagina contiene un link a {link}")
            count += 1
    return count


def add_similarity_edges(g: nx.DiGraph, articles: list[Article], threshold: float = 0.6,
                         min_chars: int = 400) -> int:
    """TF-IDF su parole e bigrammi + similarità coseno, tra articoli di domini diversi."""
    corpus = [a for a in articles if len(a.text) >= min_chars]
    if len(corpus) < 2:
        return 0
    max_df = 0.9 if len(corpus) >= 10 else 1.0  # con pochi documenti si terrebbero fuori i termini comuni
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_df=max_df, sublinear_tf=True)
    try:
        matrix = vectorizer.fit_transform([a.text for a in corpus])
    except ValueError:
        return 0
    sims = cosine_similarity(matrix)
    count = 0
    for i, j in combinations(range(len(corpus)), 2):
        a, b = corpus[i], corpus[j]
        score = float(sims[i, j])
        if a.domain == b.domain or score < threshold:
            continue
        g.add_edge(a.url, b.url, kind="similar_text", strength="moderate" if score >= 0.8 else "weak",
                   score=round(score, 3),
                   evidence=f"similarità TF-IDF coseno {score:.2f} (soglia {threshold:.2f}): "
                            "ripubblicazione, riscrittura o fonte comune")
        count += 1
    return count


def add_dns_edges(g: nx.DiGraph, domains: set[str]) -> int:
    """Risoluzione DNS corrente, con data dell'osservazione."""
    when = _now()
    count = 0
    for domain in sorted(domains):
        try:
            infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        for ip in sorted({info[4][0] for info in infos}):
            g.add_node(f"ip:{ip}", kind="ip", label=ip)
            g.add_edge(domain, f"ip:{ip}", kind="resolves_to", strength="weak", date=when,
                       evidence=f"{domain} risolve in {ip} (osservato {when}); "
                                "CDN e hosting condivisi servono molti siti dallo stesso IP")
            count += 1
    return count


def add_ads_edges(g: nx.DiGraph, records: list[AdsTxt]) -> int:
    """Account DIRECT e OWNERDOMAIN condivisi tra almeno due domini."""
    direct: dict[tuple[str, str], set[str]] = defaultdict(set)
    owners: dict[str, set[str]] = defaultdict(set)
    for rec in records:
        for item in rec.direct:
            direct[item].add(rec.domain)
        if rec.owner_domain:
            owners[rec.owner_domain].add(rec.domain)
        if rec.domain in g:
            g.nodes[rec.domain]["ads_txt"] = rec.url or rec.error
    count = 0
    for (system, account), domains in direct.items():
        if len(domains) < 2:
            continue
        node = f"ads:{system}/{account}"
        publisher_id = is_publisher_id(system, account)
        g.add_node(node, kind="ads", label=f"{system} {account}")
        for d in sorted(domains):
            g.add_edge(d, node, kind="ads_direct", strength="moderate" if publisher_id else "weak",
                       evidence=f"ads.txt di {d} dichiara {system}, {account}, DIRECT "
                                f"(stesso account su {len(domains)} domini; "
                                + ("ID editore Google)" if publisher_id else
                                   "piattaforma terza: righe spesso fornite dalla concessionaria a tutti i clienti)"))
            count += 1
    for owner, domains in owners.items():
        if len(domains) < 2:
            continue
        node = f"owner:{owner}"
        g.add_node(node, kind="owner", label=f"OWNERDOMAIN {owner}")
        for d in sorted(domains):
            g.add_edge(d, node, kind="ads_owner", strength="moderate",
                       evidence=f"ads.txt di {d} dichiara OWNERDOMAIN={owner}")
            count += 1
    return count


def is_publisher_id(system: str, account: str) -> bool:
    """ID editore Google (AdSense / Ad Manager): identifica l'account del singolo editore."""
    return system in ("google.com", "googlesyndication.com") and account.lower().startswith("pub-")


def add_cert_timeline(g: nx.DiGraph, certs_by_domain: dict[str, list[Certificate]]) -> None:
    """Primo e ultimo certificato noto per dominio: una cronologia di attività del sito."""
    for domain, certs in certs_by_domain.items():
        if domain not in g or not certs:
            continue
        dates = sorted(c.not_before for c in certs if c.not_before)
        if dates:
            g.nodes[domain].update(first_cert=dates[0][:10], last_cert=dates[-1][:10], cert_count=len(certs))


def add_cert_edges(g: nx.DiGraph, shared: list[tuple[Certificate, set[str]]]) -> int:
    count = 0
    for cert, domains in shared:
        node = f"cert:{cert.crtsh_id}"
        many = len(cert.names) > SHARED_CERT_NAMES
        g.add_node(node, kind="cert", label=f"cert {cert.not_before[:10]}",
                   issuer=cert.issuer, names=len(cert.names), url=f"https://crt.sh/?id={cert.crtsh_id}")
        for d in sorted(domains):
            g.add_edge(d, node, kind="shared_certificate", strength="weak" if many else "moderate",
                       date=cert.not_before,
                       evidence=f"certificato crt.sh #{cert.crtsh_id} ({cert.issuer}), valido "
                                f"{cert.not_before[:10]} → {cert.not_after[:10]}, copre {len(cert.names)} nomi"
                                + (" (probabile certificato condiviso di CDN)" if many else ""))
            count += 1
    return count


def filter_graph(g: nx.DiGraph, min_strength: str = "weak", kinds: set[str] | None = None) -> nx.DiGraph:
    """Tiene solo gli archi abbastanza forti (e dei tipi richiesti); toglie i nodi rimasti isolati."""
    floor = STRENGTH_ORDER[min_strength]
    h = nx.DiGraph()
    h.add_nodes_from(g.nodes(data=True))
    for s, t, data in g.edges(data=True):
        if data.get("kind") == "published_on" or (
            STRENGTH_ORDER.get(data.get("strength", "weak"), 0) >= floor
            and (not kinds or data.get("kind") in kinds)
        ):
            h.add_edge(s, t, **data)
    h.remove_nodes_from([n for n in list(h.nodes) if h.degree(n) == 0 and h.nodes[n].get("kind") != "domain"])
    return h


def summary(g: nx.DiGraph) -> dict:
    kinds: dict[str, int] = defaultdict(int)
    for _, _, data in g.edges(data=True):
        kinds[data.get("kind", "?")] += 1
    return dict(kinds)


def domain_rows(g: nx.DiGraph) -> list[dict]:
    """Riepilogo per dominio: fonti, cronologia certificati, IP, account e collegamenti."""
    rows = []
    for node, data in sorted(g.nodes(data=True)):
        if data.get("kind") != "domain":
            continue
        neigh: dict[str, set[str]] = defaultdict(set)
        for _, target, edata in g.out_edges(node, data=True):
            neigh[edata.get("kind", "")].add(g.nodes[target].get("label", target))
        articles = [s for s, _, e in g.in_edges(node, data=True) if e.get("kind") == "published_on"]
        rows.append({
            "domain": node,
            "documented_in": "; ".join(data.get("documented_in", [])),
            "articles": len(articles),
            "first_cert": data.get("first_cert", ""),
            "last_cert": data.get("last_cert", ""),
            "ips": "; ".join(sorted(neigh["resolves_to"])),
            "ads_accounts_shared": "; ".join(sorted(neigh["ads_direct"])),
            "owner_domain_shared": "; ".join(sorted(neigh["ads_owner"])),
            "shared_certificates": len(neigh["shared_certificate"]),
            "ads_txt": data.get("ads_txt", ""),
        })
    return rows


def export(g: nx.DiGraph, outdir: Path, html: bool = True) -> dict[str, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {"edges": outdir / "edges.csv", "domains": outdir / "domains.csv", "graph": outdir / "graph.json"}

    rows = domain_rows(g)
    with paths["domains"].open("w", newline="", encoding="utf-8") as fh:
        fields = ["domain", "documented_in", "articles", "first_cert", "last_cert", "ips",
                  "ads_accounts_shared", "owner_domain_shared", "shared_certificates", "ads_txt"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    with paths["edges"].open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["source", "target", "kind", "strength", "score", "date", "evidence"])
        for s, t, data in g.edges(data=True):
            writer.writerow([s, t, data.get("kind"), data.get("strength"), data.get("score", ""),
                             data.get("date", ""), data.get("evidence")])

    try:
        payload = nx.node_link_data(g, edges="links")
    except TypeError:  # networkx < 3.4
        payload = nx.node_link_data(g)
    payload["meta"] = {"generated": _now(), "strength_legend": STRENGTH_NOTE, "edges_by_kind": summary(g)}
    paths["graph"].write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    if html:
        from pyvis.network import Network

        net = Network(height="900px", width="100%", directed=True, bgcolor="#0b1020", font_color="#e2e8f0",
                      cdn_resources="remote", filter_menu=True, select_menu=True)
        sizes = {"domain": 22, "article": 10}
        for node, data in g.nodes(data=True):
            kind = data.get("kind", "domain")
            tooltip = "\n".join(f"{k}: {v}" for k, v in data.items() if v not in ("", None, []))
            net.add_node(node, label=data.get("label", node), title=f"{node}\n{tooltip}", kind=kind,
                         color=COLORS.get(kind, "#cbd5e1"), shape="dot", size=sizes.get(kind, 12))
        for s, t, data in g.edges(data=True):
            net.add_edge(s, t, title=f"{data.get('kind')} [{data.get('strength')}]\n{data.get('evidence')}",
                         kind=data.get("kind"), strength=data.get("strength"),
                         color=EDGE_COLORS.get(data.get("kind"), "#94a3b8"),
                         dashes=data.get("strength") == "weak")
        net.barnes_hut()
        paths["html"] = outdir / "graph.html"
        paths["html"].write_text(net.generate_html(notebook=False), encoding="utf-8")
    return paths
