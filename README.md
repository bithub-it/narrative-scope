# NarrativeScope

Prototipo Python per mappare **relazioni osservabili** tra articoli e siti web:
link espliciti, testi molto simili, risoluzione DNS corrente. Produce un grafo
navigabile in HTML e due file di dati (CSV e JSON) per controllare ogni relazione.

NarrativeScope **non** assegna punteggi di propaganda, **non** etichetta i siti e
**non** dimostra coordinamento o proprietà comune. Mostra indizi, ognuno con la
sua spiegazione, da verificare a mano.

## Installazione

Richiede Python 3.9 o superiore.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

Ricerca su GDELT DOC 2.0, solo metadati (nessuna pagina scaricata, nessun DNS):

```bash
python -m narrativescope --query '"Portal Kombat"' --max-results 40 --no-fetch --no-dns --output output
```

Analisi completa di un elenco di URL scelti dall'analista (uno per riga):

```bash
python -m narrativescope --urls urls.txt --threshold 0.6 --output output
```

Opzioni utili: `--timespan 24h|7d|3m`, `--delay 2`, `--max-bytes 1000000`,
`--no-html`, `-v`. Elenco completo: `python -m narrativescope --help`.

## Output

- `output/graph.html` – grafo interattivo (domini ciano, articoli viola, IP grigi; archi tratteggiati = segnali deboli).
- `output/edges.csv` – una riga per relazione: `source, target, kind, strength, score, evidence`.
- `output/graph.json` – grafo in formato node-link di NetworkX, con legenda delle categorie.

## Tipi di arco

| kind | strength | Cosa significa | Cosa NON significa |
|---|---|---|---|
| `published_on` | fact | l'articolo è ospitato su quel dominio | – |
| `links_to` | moderate | la pagina cita esplicitamente un altro articolo o dominio del corpus | proprietà comune |
| `similar_text` | moderate (≥0,80) / weak | testi molto simili secondo TF-IDF + coseno | coordinamento: può essere la stessa agenzia |
| `resolves_to` | weak | il dominio risolve oggi in quell'IP | stesso proprietario: CDN e hosting condivisi sono la norma |

La similarità TF-IDF funziona tra testi nella stessa lingua: non riconosce la
stessa narrazione tradotta. Il DNS è una fotografia del momento, non lo storico.

## Sicurezza e buone maniere

- Solo `http`/`https` su porte 80/443; rifiutati indirizzi privati, loopback, link-local, riservati.
- Redirect seguiti a mano (max 3) e ricontrollati; limite di dimensione; ritardo tra richieste allo stesso host; `robots.txt` rispettato.
- **Limite noto:** il controllo DNS e la connessione usano due risoluzioni distinte, quindi non è una difesa completa contro il DNS rebinding. Usa lo strumento in locale; non esporlo come servizio che scarica URL forniti da altri.
- Rispetta condizioni d'uso delle fonti, diritti sui contenuti e limiti di frequenza dell'API GDELT.

## Test

```bash
pip install pytest
python -m pytest -q
```

## Licenza

MIT, vedi `LICENSE`.
