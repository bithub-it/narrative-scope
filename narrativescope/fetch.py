"""Download di pagine pubbliche con protezione da SSRF e DNS rebinding.

Il punto chiave è dove avviene il controllo degli indirizzi. Validare l'URL e poi
lasciare che la libreria HTTP risolva di nuovo il nome apre una finestra fra controllo
e uso: un DNS ostile può rispondere con un IP pubblico alla prima domanda e con
127.0.0.1 alla seconda (DNS rebinding).

Qui la risoluzione avviene una sola volta, dentro la connessione: il nome viene
risolto, ogni indirizzo restituito viene validato e il socket si apre esattamente
verso uno di quegli indirizzi. Il nome host originale resta usato per SNI, verifica
del certificato TLS e intestazione Host, quindi HTTPS funziona normalmente.

Altre regole:
- solo http/https, porte 80/443, niente credenziali nell'URL;
- rifiutati indirizzi privati, loopback, link-local, riservati, multicast, CGNAT;
- redirect seguiti a mano (max 3), ognuno ricontrollato;
- proxy da variabili d'ambiente ignorati (un proxy farebbe la risoluzione al posto nostro);
- limite di dimensione, solo contenuti testuali, ritardo per host, robots.txt.
"""

from __future__ import annotations

import ipaddress
import socket
import time
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from . import __version__

USER_AGENT = f"NarrativeScope/{__version__} (+https://github.com/bithub-it/narrative-scope)"
ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 3


class FetchRefused(Exception):
    """L'URL o l'indirizzo di destinazione non supera i controlli di sicurezza."""


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    content_type: str
    text: str


# --- validazione indirizzi -------------------------------------------------

def _check_ip(ip: str) -> None:
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if not addr.is_global or addr.is_multicast or addr.is_reserved:
        raise FetchRefused(f"indirizzo non pubblico: {ip}")


def resolve_public(host: str, port: int = 443) -> list[str]:
    """Risolve l'host una volta e restituisce gli IP, solo se sono tutti pubblici."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchRefused(f"DNS non risolto per {host}: {exc}") from exc
    ips = list(dict.fromkeys(info[4][0] for info in infos))
    if not ips:
        raise FetchRefused(f"nessun indirizzo per {host}")
    for ip in ips:
        _check_ip(ip)
    return ips


def check_url(url: str) -> None:
    """Controlli sintattici sull'URL; gli indirizzi si validano alla connessione."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchRefused(f"schema non ammesso: {parts.scheme or '(vuoto)'}")
    if not parts.hostname:
        raise FetchRefused("URL senza host")
    if parts.username or parts.password:
        raise FetchRefused("credenziali nell'URL non ammesse")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise FetchRefused("porta non valida") from exc
    if port not in ALLOWED_PORTS:
        raise FetchRefused(f"porta non ammessa: {port}")


# --- connessioni con IP verificato ----------------------------------------

class _PinnedMixin:
    """Risolve e valida il nome dentro la connessione, poi si collega a quell'IP."""

    def _new_conn(self):  # type: ignore[override]
        host = self._dns_host
        ips = resolve_public(host, self.port)
        last_exc: Exception | None = None
        for ip in ips:
            self._dns_host = ip
            try:
                return super()._new_conn()
            except Exception as exc:  # prova l'indirizzo successivo
                last_exc = exc
            finally:
                self._dns_host = host
        assert last_exc is not None
        raise last_exc


class PinnedHTTPConnection(_PinnedMixin, HTTPConnection):
    pass


class PinnedHTTPSConnection(_PinnedMixin, HTTPSConnection):
    pass


class _PinnedHTTPPool(HTTPConnectionPool):
    ConnectionCls = PinnedHTTPConnection


class _PinnedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection


class PinnedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _PinnedHTTPPool, "https": _PinnedHTTPSPool}


def safe_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False  # nessun proxy da HTTP(S)_PROXY: la risoluzione resta nostra
    adapter = PinnedAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers["User-Agent"] = USER_AGENT
    return session


# --- fetcher ----------------------------------------------------------------

class PoliteFetcher:
    def __init__(
        self,
        delay: float = 1.5,
        timeout: float = 15.0,
        max_bytes: int = 2_000_000,
        respect_robots: bool = True,
    ) -> None:
        self.delay = delay
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.respect_robots = respect_robots
        self.session = safe_session()
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
        check_url(url)
        self._wait(urlsplit(url).hostname or "")
        return self.session.get(url, timeout=self.timeout, stream=True, allow_redirects=False)

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
                    parser.parse(self._read_limited(resp).decode("utf-8", "replace").splitlines())
                    self._robots[base] = parser
                else:
                    resp.close()
                    self._robots[base] = None
            except (requests.RequestException, FetchRefused):
                self._robots[base] = None
        parser = self._robots[base]
        return True if parser is None else parser.can_fetch(USER_AGENT, url)

    def get(self, url: str, check_robots: bool = True) -> FetchResult:
        if check_robots and not self.allowed_by_robots(url):
            raise FetchRefused("escluso da robots.txt")
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            resp = self._raw_get(current)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                resp.close()
                if not location:
                    raise FetchRefused("redirect senza destinazione")
                current = urljoin(current, location)
                continue
            if resp.status_code >= 400:
                resp.close()
                raise FetchRefused(f"HTTP {resp.status_code}")
            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype and "text" not in ctype:
                resp.close()
                raise FetchRefused(f"contenuto non testuale: {ctype or 'sconosciuto'}")
            body = self._read_limited(resp)
            encoding = resp.encoding or "utf-8"
            return FetchResult(url, current, resp.status_code, ctype, body.decode(encoding, "replace"))
        raise FetchRefused("troppi redirect")
