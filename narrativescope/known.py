"""Import di elenchi di domini già documentati da fonti pubbliche.

Formato CSV (intestazione obbligatoria, colonne extra ignorate):

    domain,source,url,date,note
    pravda-fr.com,VIGINUM Portal Kombat,https://www.sgdsn.gouv.fr/...,2024-02-12,ecosistema pravda

Solo `domain` e `source` sono obbligatori. Ogni dominio diventa un nodo del grafo
collegato alla fonte che lo documenta, con data e link: così sulla mappa si distingue
ciò che è già attribuito da una fonte pubblica da ciò che emerge dall'analisi.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .gdelt import domain_of


@dataclass
class KnownDomain:
    domain: str
    source: str
    url: str = ""
    date: str = ""
    note: str = ""


def _clean_domain(value: str) -> str:
    value = value.strip().lower().replace("[.]", ".")
    if "://" in value:
        return domain_of(value)
    value = value.split("/", 1)[0]
    return value[4:] if value.startswith("www.") else value


def load(path: Path) -> list[KnownDomain]:
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = {"domain", "source"} - {c.strip().lower() for c in (reader.fieldnames or [])}
        if missing:
            raise ValueError(f"{path}: colonne mancanti {sorted(missing)}")
        rows = []
        for row in reader:
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            domain = _clean_domain(row.get("domain", ""))
            if not domain or domain.startswith("#"):
                continue
            rows.append(KnownDomain(domain, row.get("source", ""), row.get("url", ""),
                                    row.get("date", ""), row.get("note", "")))
    return rows
