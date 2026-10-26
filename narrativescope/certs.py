"""Storico dei certificati TLS dai log di Certificate Transparency (crt.sh).

Ogni certificato pubblico finisce nei log CT con date di validità e l'elenco dei nomi
coperti (SAN). Un certificato che copre più domini del corpus indica che qualcuno ha
chiesto un unico certificato per tutti: è un legame tra i domini, datato.

Eccezione nota: i certificati condivisi delle CDN (per esempio i vecchi certificati
Cloudflare con decine di clienti nello stesso SAN). Per questo i certificati con molti
nomi vengono marcati come segnale debole.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from .fetch import USER_AGENT

CRTSH_URL = "https://crt.sh/"
SHARED_CERT_NAMES = 25  # oltre questa soglia di nomi il certificato è probabilmente condiviso


@dataclass
class Certificate:
    key: str
    crtsh_id: int
    issuer: str
    not_before: str
    not_after: str
    names: set[str] = field(default_factory=set)


def normalize_name(name: str) -> str:
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if name.startswith("www."):
        name = name[4:]
    return name


def parse_crtsh(entries: list[dict]) -> list[Certificate]:
    """Converte la risposta JSON di crt.sh, unendo precertificato e certificato finale."""
    certs: dict[str, Certificate] = {}
    for entry in entries:
        serial = str(entry.get("serial_number") or entry.get("id"))
        issuer = entry.get("issuer_name", "")
        key = f"{entry.get('issuer_ca_id', issuer)}:{serial}"
        names = {normalize_name(n) for n in str(entry.get("name_value", "")).split("\n") if n.strip()}
        if entry.get("common_name"):
            names.add(normalize_name(entry["common_name"]))
        cert = certs.get(key)
        if cert is None:
            certs[key] = Certificate(
                key=key,
                crtsh_id=int(entry.get("id", 0)),
                issuer=issuer,
                not_before=str(entry.get("not_before", "")),
                not_after=str(entry.get("not_after", "")),
                names=names,
            )
        else:
            cert.names |= names
            cert.crtsh_id = min(cert.crtsh_id, int(entry.get("id", cert.crtsh_id)))
    return list(certs.values())


def lookup(domain: str, timeout: float = 60.0, retries: int = 2) -> list[Certificate]:
    params = {"q": domain, "output": "json"}
    for attempt in range(retries + 1):
        try:
            resp = requests.get(CRTSH_URL, params=params, timeout=timeout, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                return parse_crtsh(resp.json())
        except (requests.RequestException, ValueError):
            pass
        time.sleep(3 * (attempt + 1))  # crt.sh è spesso sovraccarico: si riprova con calma
    return []


def shared_certificates(certs_by_domain: dict[str, list[Certificate]], domains: set[str]) -> list[tuple[Certificate, set[str]]]:
    """Certificati che coprono almeno due domini del corpus."""
    unique: dict[str, Certificate] = {}
    for certs in certs_by_domain.values():
        for cert in certs:
            unique.setdefault(cert.key, cert)
    shared = []
    for cert in unique.values():
        covered = {d for d in domains if d in cert.names}
        if len(covered) >= 2:
            shared.append((cert, covered))
    return shared
