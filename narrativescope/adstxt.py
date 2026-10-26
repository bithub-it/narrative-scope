"""Lettura e confronto dei file ads.txt.

ads.txt (IAB Tech Lab) elenca chi è autorizzato a vendere gli spazi pubblicitari di
un dominio. Due elementi sono utili per collegare siti:

- record DIRECT: account pubblicitario controllato direttamente dall'editore
  (es. "google.com, pub-1234567890, DIRECT"). Lo stesso account DIRECT su più domini
  indica che incassano sullo stesso account.
- OWNERDOMAIN (ads.txt 1.1): dominio dell'entità che possiede il sito, dichiarato
  dall'editore stesso.

I record RESELLER vengono ignorati: le stesse concessionarie compaiono su migliaia di
siti indipendenti.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .fetch import FetchRefused, PoliteFetcher


@dataclass
class AdsTxt:
    domain: str
    url: str = ""
    direct: set[tuple[str, str]] = field(default_factory=set)  # (sistema, id account)
    owner_domain: str = ""
    manager_domains: set[str] = field(default_factory=set)
    error: str = ""


def parse(text: str, domain: str = "", url: str = "") -> AdsTxt:
    result = AdsTxt(domain=domain, url=url)
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line and "," not in line.split("=", 1)[0]:
            key, value = (part.strip() for part in line.split("=", 1))
            key = key.upper()
            if key == "OWNERDOMAIN":
                result.owner_domain = value.lower()
            elif key == "MANAGERDOMAIN":
                result.manager_domains.add(value.split(",")[0].strip().lower())
            continue
        fields = [part.strip() for part in line.split(",")]
        if len(fields) < 3:
            continue
        system, account, relation = fields[0].lower(), fields[1], fields[2].upper()
        if relation == "DIRECT" and system and account:
            result.direct.add((system, account))
    return result


def looks_like_ads_txt(text: str) -> bool:
    """Scarta pagine HTML servite al posto di ads.txt (molti siti rispondono 200 a tutto)."""
    head = text.lstrip()[:200].lower()
    return not head.startswith("<") and "<html" not in head


def fetch(fetcher: PoliteFetcher, domain: str) -> AdsTxt:
    last_error = ""
    for url in (f"https://{domain}/ads.txt", f"http://{domain}/ads.txt"):
        try:
            res = fetcher.get(url, check_robots=False)
        except FetchRefused as exc:
            last_error = str(exc)
            continue
        except Exception as exc:  # errori di rete: si prova lo schema successivo
            last_error = str(exc)[:200]
            continue
        if not looks_like_ads_txt(res.text):
            return AdsTxt(domain=domain, url=res.final_url, error="risposta HTML, nessun ads.txt")
        return parse(res.text, domain, res.final_url)
    return AdsTxt(domain=domain, error=last_error or "ads.txt non disponibile")
