import http.server
import json
import threading
from functools import partial
from pathlib import Path

import networkx as nx
import pytest

from narrativescope import cli, fetch
from narrativescope.extract import extract
from narrativescope.gdelt import Article, parse_artlist
from narrativescope.graph import add_articles, add_link_edges, add_similarity_edges, export

SHARED = (
    "Il ministero ha annunciato un nuovo piano per le infrastrutture energetiche del paese, "
    "con investimenti pluriennali nelle reti elettriche, negli impianti di accumulo e nelle "
    "interconnessioni con i paesi vicini. Secondo il comunicato, i lavori partiranno entro la "
    "primavera e coinvolgeranno operatori pubblici e privati, con controlli trimestrali sui "
    "cantieri e una relazione annuale al parlamento sullo stato di avanzamento delle opere. "
)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://10.0.0.5/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://example.com:8080/",
    "http://user:pw@example.com/",
])
def test_check_url_refuses_unsafe(url):
    with pytest.raises(fetch.FetchRefused):
        fetch.check_url(url)


def test_parse_artlist():
    payload = {"articles": [
        {"url": "https://www.example.org/a", "title": "A", "seendate": "20261020T101500Z",
         "domain": "example.org", "language": "Italian", "sourcecountry": "Italy"},
        {"title": "senza url"},
    ]}
    arts = parse_artlist(payload)
    assert len(arts) == 1
    assert arts[0].domain == "example.org"
    assert arts[0].seen.startswith("2026-10-20T10:15:00")


def test_extract_text_and_links():
    html = """<html><head><title>T</title><script>x()</script></head><body>
    <nav><a href="/menu">menu</a></nav>
    <article><p>%s</p><a href="https://other.example/x#frag">fonte</a></article></body></html>""" % SHARED
    title, text, links = extract(html, "https://site.example/post")
    assert title == "T"
    assert "infrastrutture energetiche" in text and "x()" not in text
    assert "https://other.example/x" in links
    assert "https://site.example/menu" in links


def test_graph_edges_are_explained(tmp_path):
    a = Article(url="https://a.example/1", domain="a.example", text=SHARED * 2,
                outlinks=["https://b.example/2", "https://a.example/interno"])
    b = Article(url="https://b.example/2", domain="b.example", text=SHARED * 2)
    c = Article(url="https://c.example/3", domain="c.example",
                text="Testo completamente diverso sulla stagione calcistica e sui risultati del campionato " * 10)
    g = nx.DiGraph()
    add_articles(g, [a, b, c])
    assert add_link_edges(g, [a, b, c]) == 1
    assert add_similarity_edges(g, [a, b, c], threshold=0.6) == 1
    for _, _, data in g.edges(data=True):
        assert data["evidence"] and data["strength"] in {"fact", "moderate", "weak"}
    paths = export(g, tmp_path)
    graph = json.loads(paths["graph"].read_text(encoding="utf-8"))
    assert graph["meta"]["strength_legend"]
    assert "similar_text" in paths["edges"].read_text(encoding="utf-8")
    assert paths["html"].exists()


def test_end_to_end_with_local_server(tmp_path, monkeypatch):
    site = tmp_path / "site"
    site.mkdir()
    (site / "one.html").write_text(f"<html><body><article><p>{SHARED}</p><p>{SHARED}</p></article></body></html>")
    (site / "two.html").write_text(f"<html><body><article><p>{SHARED}</p><p>{SHARED}</p></article></body></html>")
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(site))
    handler.log_message = lambda *a, **k: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    # Il server di test è su loopback: in produzione verrebbe rifiutato, quindi qui
    # disattiviamo solo il controllo degli indirizzi e consentiamo la porta effimera.
    monkeypatch.setattr(fetch, "check_url", lambda url: None)
    urls = tmp_path / "urls.txt"
    # due host diversi che puntano allo stesso server locale
    urls.write_text(f"http://127.0.0.1:{port}/one.html\nhttp://localhost:{port}/two.html\n")
    out = tmp_path / "out"
    try:
        rc = cli.main(["--urls", str(urls), "--no-dns", "--delay", "0", "--output", str(out)])
    finally:
        server.shutdown()
    assert rc == 0
    edges = (out / "edges.csv").read_text(encoding="utf-8")
    assert "similar_text" in edges
    assert (out / "graph.html").exists()
