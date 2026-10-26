"""Download prudente di pagine pubbliche.

Controlli applicati prima di ogni richiesta:
- solo schemi http/https e porte 80/443;
- l'host viene risolto e si rifiutano indirizzi privati, loopback, link-local,
  riservati, multicast e non specificati;
- redirect seguiti a mano (massimo 3), ricontrollando ogni destinazione;
- dimensione massima del corpo, timeout, ritardo minimo tra richieste allo stesso host;
- robots.txt rispettato quando leggibile.

Limite noto: la risoluzione DNS fatta per il controllo e quella fatta dalla libreria
HTTP sono separate. Un server DNS ostile può rispondere in modo diverso fra le due
(DNS rebinding). Per questo il programma va usato in locale da un singolo analista e
non esposto come servizio che scarica URL forniti da terzi.
"""

from __future__ import annotations

import ipaddress
import socket
import time
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests

USER_AGENT = "NarrativeScope/0.1 (+ricerca OSINT locale; https://able2code.com)"
ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 3


class FetchRefused(Exception):
    """L'URL non supera i controlli di sicurezza."""


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    content_type: str
    text: str


def _check_ip(ip: str) -> None:
    addr = ipaddress.ip_address(ip)
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or not addr.is_global
    ):
        raise FetchRefused(f"indirizzo non pubblico: {ip}")


def resolve_public(host: str) -> list[str]:
    """Risolve l'host e verifica che tutti gli indirizzi siano pubblici."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchRefused(f"DNS non risolto per {host}: {exc}") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise FetchRefused(f"nessun indirizzo per {host}")
    for ip in ips:
        _check_ip(ip)
    return ips


def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchRefused(f"schema non ammesso: {parts.scheme or '(vuoto)'}")
    if not parts.hostname:
        raise FetchRefused("URL senza host")
    if parts.username or parts.password:
        raise FetchRefused("credenziali nell'URL non ammesse")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise FetchRefused(f"porta non ammessa: {port}")
    resolve_public(parts.hostname)


class PoliteFetcher:
    def __init__(
        self,
        delay: float = 1.5,
        timeout: float = 15.0,
        max_bytes: int = 2_000_000,
        respect_robots: bool = True,
        resolver_check: bool = True,
    ) -> None:
        self.delay = delay
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.respect_robots = respect_robots
        self.resolver_check = resolver_check
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self._last_hit: dict[str, float] = {}
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    def _wait(self, host: str) -> None:
        last = self._last_hit.get(host)
        if last is not None:
            pause = self.delay - (time.monotonic() - last)
            if pause > 0:
                time.sleep(pause)
        self._last_hit[host] = time.monotonic()

    def _raw_get(self, url: str) -> requests.Response:
        if self.resolver_check:
            check_url(url)
        host = urlsplit(url).hostname or ""
        self._wait(host)
        resp = self.session.get(url, timeout=self.timeout, stream=True, allow_redirects=False)
        return resp

    def _read_limited(self, resp: requests.Response) -> bytes:
        declared = resp.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            resp.close()
            raise FetchRefused(f"documento troppo grande ({declared} byte)")
        chunks, total = [], 0
        for chunk in resp.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > self.max_bytes:
                resp.close()
                raise FetchRefused(f"documento oltre {self.max_bytes} byte")
            chunks.append(chunk)
        return b"".join(chunks)

    def allowed_by_robots(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parts = urlsplit(url)
        base = f"{parts.scheme}://{parts.netloc}"
        if base not in self._robots:
            parser = urllib.robotparser.RobotFileParser()
            try:
                resp = self._raw_get(base + "/robots.txt")
                if resp.status_code == 200:
                    body = self._read_limited(resp).decode("utf-8", "replace")
                    parser.parse(body.splitlines())
                    self._robots[base] = parser
                else:
                    resp.close()
                    self._robots[base] = None  # nessun robots.txt leggibile: nessuna restrizione dichiarata
            except (requests.RequestException, FetchRefused):
                self._robots[base] = None
        parser = self._robots[base]
        return True if parser is None else parser.can_fetch(USER_AGENT, url)

    def get(self, url: str) -> FetchResult:
        if not self.allowed_by_robots(url):
            raise FetchRefused("escluso da robots.txt")
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            resp = self._raw_get(current)
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                resp.close()
                if not location:
                    raise FetchRefused("redirect senza destinazione")
                current = urljoin(current, location)
                continue
            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype and "text" not in ctype:
                resp.close()
                raise FetchRefused(f"contenuto non testuale: {ctype or 'sconosciuto'}")
            body = self._read_limited(resp)
            encoding = resp.encoding or "utf-8"
            return FetchResult(url, current, resp.status_code, ctype, body.decode(encoding, "replace"))
        raise FetchRefused("troppi redirect")
