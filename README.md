# NarrativeScope

Strumento OSINT in Python per mappare le relazioni tra siti e articoli: link,
testi ripubblicati, DNS, account pubblicitari in `ads.txt`, certificati TLS dai log
di Certificate Transparency ed elenchi di domini già documentati da fonti pubbliche.

Il risultato è un grafo navigabile in HTML più due file di dati (CSV e JSON).
Ogni arco riporta cosa è stato osservato (`evidence`) e quanto pesa come indizio
(`strength`), così ogni collegamento si può verificare a mano.

## Approfondimenti

- [Mappare le reti di disinformazione con Python: GDELT, ads.txt, certificati TLS e grafi](https://able2code.com/sicurezza/narrativescope-osint-python-grafo-disinformazione/) – Able2Code
- [Propaganda, SEO e motori di ricerca: come riconoscere le reti che amplificano le informazioni](https://bithub.it/blog/propaganda-seo-reti-siti-motori-ricerca/) – Bithub

## Installazione

Python 3.9 o superiore.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

Notizie recenti da GDELT, con pagine scaricate e confrontate:

```bash
python -m narrativescope --query '"Portal Kombat"' --timespan 3m --output output
```

Partire da un elenco documentato e cercare legami infrastrutturali:

```bash
python -m narrativescope --known examples/portal-kombat.csv --ads --certs --output output
```

Combinare le sorgenti e tenere solo gli indizi specifici:

```bash
python -m narrativescope --query '"Portal Kombat"' --known examples/portal-kombat.csv \
  --ads --certs --min-strength moderate --output output
```

### Sorgenti

| Opzione | Cosa fa |
|---|---|
| `--query` | ricerca su GDELT DOC 2.0; `--timespan 24h\|7d\|3m` oppure `--since/--until AAAA-MM-GG` |
| `--urls file.txt` | un URL per riga |
| `--known file.csv` | domini già documentati: `domain,source[,url,date,note]` |

### Segnali

| Opzione | Arco | Forza |
|---|---|---|
| (sempre) | `published_on` articolo → dominio | fact |
| (con le pagine scaricate) | `links_to` citazione esplicita | moderate |
| (con le pagine scaricate) | `similar_text` TF-IDF + coseno, soglia `--threshold` | moderate ≥ 0,80, altrimenti weak |
| (default, `--no-dns` per saltare) | `resolves_to` IP corrente | weak |
| `--ads` | `ads_direct` stesso account DIRECT in `ads.txt` | moderate per gli ID editore Google (`pub-`), weak per le piattaforme terze |
| `--ads` | `ads_owner` stesso `OWNERDOMAIN` dichiarato | moderate |
| `--certs` | `shared_certificate` stesso certificato su più domini (crt.sh, con date) | moderate, weak se il certificato copre più di 25 nomi |
| `--certs` | cronologia per dominio: primo e ultimo certificato noto (`first_cert`, `last_cert`) | – |
| `--known` | `documented_in` dominio → fonte | fact |

### Filtri

- `--min-strength weak|moderate|fact` scarta gli archi sotto la soglia.
- `--edge-kinds ads_direct,shared_certificate` tiene solo alcuni tipi.
- In `graph.html` il menu di filtro permette di selezionare nodi e archi per tipo e forza.

## Output

- `output/graph.html` – grafo interattivo. Domini ciano, articoli viola, IP grigi, account pubblicitari gialli, proprietari dichiarati arancio, certificati verdi, fonti rosa; archi deboli tratteggiati.
- `output/edges.csv` – `source, target, kind, strength, score, date, evidence`.
- `output/domains.csv` – una riga per dominio: fonti, articoli, primo e ultimo certificato, IP, account e certificati condivisi.
- `output/graph.json` – formato node-link di NetworkX, importabile in Gephi, con legenda e conteggi.

## Sicurezza di rete

NarrativeScope scarica URL scelti da altri (risultati GDELT, link nelle pagine), quindi
è progettato contro SSRF e DNS rebinding:

- solo `http`/`https` su porte 80/443, niente credenziali nell'URL;
- il nome host viene risolto **una sola volta, dentro la connessione**: ogni IP
  restituito viene validato (niente indirizzi privati, loopback, link-local, CGNAT,
  riservati, multicast, IPv4-mapped) e il socket si apre verso uno di quegli IP. Il
  nome originale resta usato per SNI e verifica del certificato;
- i proxy impostati da variabili d'ambiente vengono ignorati;
- redirect seguiti a mano (max 3) e ricontrollati; limite di dimensione; ritardo per host; `robots.txt` rispettato.

## Test

```bash
pip install pytest
python -m pytest -q
```

I test coprono, tra l'altro, il rifiuto di indirizzi interni, un attacco di DNS
rebinding simulato e la connessione all'IP validato.

## Licenza

MIT, vedi `LICENSE`.
