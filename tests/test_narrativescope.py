import http.server
import json
import socket
import threading
from functools import partial

import networkx as nx
import pytest

from narrativescope import adstxt, certs, cli, fetch, known
from narrativescope.extract import extract
from narrativescope.gdelt import Article, build_params, parse_artlist
from narrativescope.graph import (add_ads_edges, add_articles, add_cert_edges, add_cert_timeline, add_known,
                                  add_link_edges, add_similarity_edges, export, filter_graph)

SHARED = (
    "Il ministero ha annunciato un nuovo piano per le infrastrutture energetiche del paese, "
    "con investimenti pluriennali nelle reti elettriche, negli impianti di accumulo e nelle "
    "interconnessioni con i paesi vicini. Secondo il comunicato, i lavori partiranno entro la "
    "primavera e coinvolgeranno operatori pubblici e privati, con controlli trimestrali sui "
    "cantieri e una relazione annuale al parlamento sullo stato di avanzamento delle opere. "
)

REAL_GETADDRINFO = socket.getaddrinfo


# --- server HTTP locale per i test -------------------------------------------

class _Handler(http.server.SimpleHTTPRequestHandler):
    hits: list[str] = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).hits.append(self.path)
        super().do_GET()


@pytest.fixture
def local_site(tmp_path, monkeypatch):
    site = tmp_path / "site"
    site.mkdir()
    page = f"<html><body><article><p>{SHARED}</p><p>{SHARED}</p></article></body></html>"
    (site / "one.html").write_text(page)
    (site / "two.html").write_text(page)
    (site / "ads.txt").write_text("google.com, pub-111, DIRECT, f08c47fec0942fa0\nOWNERDOMAIN=gruppo.example\n")
    _Handler.hits = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), partial(_Handler, directory=str(site)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    monkeypatch.setattr(fetch, "ALLOWED_PORTS", {80, 443, port})
    yield port
    server.shutdown()


def fake_dns(mapping):
    """getaddrinfo finto: nome -> lista di IP (o funzione che restituisce la lista)."""
    def _resolve(host, port, *args, **kwargs):
        ips = mapping[host]() if callable(mapping.get(host)) else mapping.get(host)
        if ips is None:
            return REAL_GETADDRINFO(host, port, *args, **kwargs)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]
    return _resolve


# --- sicurezza di rete -------------------------------------------------------

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://example.com/",
    "http://example.com:8080/",
    "http://user:pw@example.com/",
])
def test_check_url_refuses_bad_urls(url):
    with pytest.raises(fetch.FetchRefused):
        fetch.check_url(url)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1",
                                "::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1"])
def test_non_public_addresses_refused(ip):
    with pytest.raises(fetch.FetchRefused):
        fetch._check_ip(ip)


def test_public_address_accepted():
    fetch._check_ip("93.184.216.34")
    fetch._check_ip("2606:4700:4700::1111")


def test_private_target_refused_at_connection(local_site, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"interno.test": ["127.0.0.1"]}))
    with pytest.raises(fetch.FetchRefused):
        fetch.PoliteFetcher(delay=0, respect_robots=False).get(f"http://interno.test:{local_site}/one.html")
    assert _Handler.hits == []


def test_dns_rebinding_blocked(local_site, monkeypatch):
    """Prima risposta pubblica, seconda interna: la connessione non deve partire."""
    answers = iter([["93.184.216.34"], ["127.0.0.1"], ["127.0.0.1"]])
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"rebind.test": lambda: next(answers)}))
    fetch.resolve_public("rebind.test")  # il "controllo" iniziale vede un IP pubblico
    with pytest.raises(fetch.FetchRefused):
        fetch.PoliteFetcher(delay=0, respect_robots=False).get(f"http://rebind.test:{local_site}/one.html")
    assert _Handler.hits == []


def test_connection_uses_the_validated_ip(local_site, monkeypatch):
    """Il nome viene risolto da NarrativeScope e il socket va all'IP validato."""
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"pinned.test": ["127.0.0.1"]}))
    validated = []
    monkeypatch.setattr(fetch, "_check_ip", lambda ip: validated.append(ip))
    res = fetch.PoliteFetcher(delay=0, respect_robots=False).get(f"http://pinned.test:{local_site}/one.html")
    assert "infrastrutture energetiche" in res.text
    assert validated == ["127.0.0.1"]
    assert _Handler.hits == ["/one.html"]


def test_env_proxy_ignored():
    assert fetch.safe_session().trust_env is False


# --- parsing -----------------------------------------------------------------

def test_parse_artlist_and_dates():
    payload = {"articles": [
        {"url": "https://www.example.org/a", "title": "A", "seendate": "20261020T101500Z",
         "domain": "example.org", "language": "Italian", "sourcecountry": "Italy"},
        {"title": "senza url"},
    ]}
    arts = parse_artlist(payload)
    assert len(arts) == 1 and arts[0].domain == "example.org"
    assert arts[0].seen.startswith("2026-10-20T10:15:00")
    params = build_params("q", since="2024-02-01", until="2024-02-29")
    assert params["startdatetime"] == "20240201000000" and params["enddatetime"] == "20240229235959"
    assert "timespan" not in params


def test_extract_text_and_links():
    html = """<html><head><title>T</title><script>x()</script></head><body>
    <nav><a href="/menu">menu</a></nav>
    <article><p>%s</p><a href="https://other.example/x#frag">fonte</a></article></body></html>""" % SHARED
    title, text, links = extract(html, "https://site.example/post")
    assert title == "T" and "infrastrutture energetiche" in text and "x()" not in text
    assert "https://other.example/x" in links and "https://site.example/menu" in links


def test_parse_ads_txt():
    rec = adstxt.parse("""# commento
google.com, pub-111, DIRECT, f08c47fec0942fa0
appnexus.com, 999, RESELLER
contact=ads@example.com
OWNERDOMAIN=Gruppo.example
MANAGERDOMAIN=gestore.example
""", "a.example")
    assert rec.direct == {("google.com", "pub-111")}
    assert rec.owner_domain == "gruppo.example"
    assert rec.manager_domains == {"gestore.example"}
    assert not adstxt.looks_like_ads_txt("<!doctype html><html>404</html>")


def test_parse_crtsh_merges_precert_and_cert():
    entries = [
        {"id": 2, "issuer_ca_id": 7, "issuer_name": "CA", "serial_number": "abc", "common_name": "a.example",
         "name_value": "a.example\nwww.b.example", "not_before": "2024-01-01T00:00:00", "not_after": "2024-04-01T00:00:00"},
        {"id": 1, "issuer_ca_id": 7, "issuer_name": "CA", "serial_number": "abc", "common_name": "a.example",
         "name_value": "*.c.example", "not_before": "2024-01-01T00:00:00", "not_after": "2024-04-01T00:00:00"},
    ]
    parsed = certs.parse_crtsh(entries)
    assert len(parsed) == 1 and parsed[0].crtsh_id == 1
    assert parsed[0].names == {"a.example", "b.example", "c.example"}
    shared = certs.shared_certificates({"a.example": parsed}, {"a.example", "b.example", "z.example"})
    assert shared[0][1] == {"a.example", "b.example"}


def test_known_csv(tmp_path):
    path = tmp_path / "known.csv"
    path.write_text("domain,source,url,date,note\nhttps://www.pravda-fr.com/x,VIGINUM,https://v.example,2024-02-12,pravda\n"
                    "news-pravda[.]com,VIGINUM,,,\n", encoding="utf-8")
    rows = known.load(path)
    assert [r.domain for r in rows] == ["pravda-fr.com", "news-pravda.com"]
    bad = tmp_path / "bad.csv"
    bad.write_text("dominio\nx.com\n")
    with pytest.raises(ValueError):
        known.load(bad)


# --- grafo -------------------------------------------------------------------

def test_graph_edges_are_explained(tmp_path):
    a = Article(url="https://a.example/1", domain="a.example", text=SHARED * 2,
                outlinks=["https://b.example/2", "https://a.example/interno"])
    b = Article(url="https://b.example/2", domain="b.example", text=SHARED * 2)
    c = Article(url="https://c.example/3", domain="c.example",
                text="Testo completamente diverso sulla stagione calcistica e sui risultati del campionato " * 10)
    g = nx.DiGraph()
    add_articles(g, [a, b, c])
    add_known(g, [known.KnownDomain("a.example", "Rapporto X", "https://x.example", "2024-02-12")])
    assert add_link_edges(g, [a, b, c]) == 1
    assert add_similarity_edges(g, [a, b, c]) == 1
    recs = [adstxt.parse("google.com, pub-1, DIRECT\nvideo.example, 77, DIRECT\nOWNERDOMAIN=o.example", d)
            for d in ("a.example", "b.example")]
    recs.append(adstxt.parse("google.com, pub-2, DIRECT", "c.example"))
    assert add_ads_edges(g, recs) == 6
    assert g["a.example"]["ads:google.com/pub-1"]["strength"] == "moderate"
    assert g["a.example"]["ads:video.example/77"]["strength"] == "weak"  # piattaforma terza
    cert = certs.Certificate("k", 5, "CA", "2024-01-01", "2024-04-01", {"a.example", "c.example"})
    assert add_cert_edges(g, [(cert, {"a.example", "c.example"})]) == 2
    old = certs.Certificate("k0", 4, "CA", "2023-02-22T00:00:00", "2023-05-23T00:00:00", {"a.example"})
    add_cert_timeline(g, {"a.example": [cert, old]})
    assert g.nodes["a.example"]["first_cert"] == "2023-02-22" and g.nodes["a.example"]["last_cert"] == "2024-01-01"
    for _, _, data in g.edges(data=True):
        assert data["evidence"] and data["strength"] in {"fact", "moderate", "weak"}
    assert "ads:google.com/pub-2" not in g  # account presente su un solo dominio: nessun nodo
    assert g.nodes["a.example"]["documented_in"] == ["Rapporto X"]

    strong = filter_graph(g, "moderate", {"ads_direct"})
    assert {d["kind"] for _, _, d in strong.edges(data=True)} == {"published_on", "ads_direct"}

    paths = export(g, tmp_path)
    graph = json.loads(paths["graph"].read_text(encoding="utf-8"))
    assert graph["meta"]["edges_by_kind"]["shared_certificate"] == 2
    assert "documented_in" in paths["edges"].read_text(encoding="utf-8")
    domains_csv = paths["domains"].read_text(encoding="utf-8")
    assert "a.example,Rapporto X,1,2023-02-22,2024-01-01" in domains_csv
    assert "filter" in paths["html"].read_text(encoding="utf-8").lower()


def test_end_to_end_with_local_server(local_site, tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"uno.test": ["127.0.0.1"], "due.test": ["127.0.0.1"]}))
    monkeypatch.setattr(fetch, "_check_ip", lambda ip: None)  # il server di prova è su loopback
    urls = tmp_path / "urls.txt"
    urls.write_text(f"http://uno.test:{local_site}/one.html\nhttp://due.test:{local_site}/two.html\n")
    known_csv = tmp_path / "known.csv"
    known_csv.write_text("domain,source\nuno.test,Elenco di prova\n")
    out = tmp_path / "out"

    # ads.txt è servito sulla porta del server di prova: si legge passando l'host con porta
    real_fetch = adstxt.fetch

    def fetch_on_test_port(fetcher, domain):
        rec = real_fetch(fetcher, f"{domain}:{local_site}")
        rec.domain = domain
        return rec

    monkeypatch.setattr(adstxt, "fetch", fetch_on_test_port)

    rc = cli.main(["--urls", str(urls), "--known", str(known_csv), "--ads", "--no-dns",
                   "--delay", "0", "--output", str(out)])
    assert rc == 0
    edges = (out / "edges.csv").read_text(encoding="utf-8")
    assert "similar_text" in edges and "documented_in" in edges and "ads_owner" in edges
    assert (out / "graph.html").exists()


def test_cli_requires_a_source(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--no-dns"])
