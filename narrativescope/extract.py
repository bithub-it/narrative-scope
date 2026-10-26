"""Estrazione di testo leggibile e link in uscita da una pagina HTML."""

from __future__ import annotations

from urllib.parse import urldefrag, urljoin, urlsplit

from bs4 import BeautifulSoup

NOISE_TAGS = ("script", "style", "noscript", "nav", "footer", "header", "aside", "form", "svg", "iframe")


def extract(html: str, base_url: str) -> tuple[str, str, list[str]]:
    """Restituisce (titolo, testo, link assoluti http/https senza frammento)."""
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    links: list[str] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = urldefrag(urljoin(base_url, anchor["href"].strip()))[0]
        if urlsplit(href).scheme in ("http", "https") and href not in seen:
            seen.add(href)
            links.append(href)

    for tag in soup(NOISE_TAGS):
        tag.decompose()
    container = soup.find("article") or soup.find("main") or soup.body or soup
    paragraphs = [p.get_text(" ", strip=True) for p in container.find_all(["p", "h1", "h2", "h3", "li"])]
    text = "\n".join(p for p in paragraphs if len(p) > 30)
    if not text:
        text = container.get_text(" ", strip=True)
    return title, text, links
