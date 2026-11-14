# Preuzimanje

Stranica: https://giljevicivan-gif.github.io/preuzmi/ (kratko: tinyurl.com/ivanscan)

Ovaj repozitorij je **javan**. Zato je ovdje sve osim Daljinskog pristupa
**šifrirano** (AES-256-GCM, lozinka). Lozinka nije nigdje u repozitoriju.

## Paketi na stranici

| Paket | Datoteka ovdje | Odakle dolazi | Kako se ažurira |
|---|---|---|---|
| **Skeniranje u mapu** | `skeniranje.bin` | privatni repo `scan-folder-setup` | **Samo**: kad se u `scan-folder-setup` podigne `VERZIJA.txt`, GitHub sam napravi ZIP, šifrira ga i objavi ovdje. |
| **Narudžbe knjiga** | `knjige.bin` | program s Ivanovog računala (bez `knjige.db`) | Ručno: `alati/paket.py objavi --id knjige ...` |
| **Daljinski pristup** | `daljinski/` (nešifrirano, po dogovoru) | zaseban program | Zamijeni `Daljinski.zip` i `Daljinski_Setup.exe`, u `verzija.json` upiši verziju i `zip_sha256`. |

Kratko o svakom paketu:

- **Skeniranje u mapu** - skripte za postavljanje skeniranja s kopirke (Canon,
  Konica) u mapu ili na email, plus dijagnostika kad ne radi. Unutra je
  `PROCITAJ-ME.txt` i `PROMJENE.txt` (što je novo u kojoj verziji).
- **Narudžbe knjiga** - program za narudžbe školskih knjiga (Python je unutra,
  ne treba instalacija). Dolazi s **praznom** bazom; prava baza kupaca
  (`knjige.db`) se nikad ne objavljuje.
- **Daljinski pristup** - program za pomoć na daljinu; sam se ažurira preko
  `daljinski/verzija.json`.

## Datoteke

- `index.html` - stranica (upiši lozinku, otključa popis i pakete u pregledniku)
- `paketi.bin` - šifrirani popis paketa (naziv, datoteka, verzija, datum)
- `<id>.bin` - šifrirani ZIP svakog paketa
- `alati/paket.py` - objava/uklanjanje paketa (lozinka iz varijable `PREUZMI_LOZINKA`)
- `alati/cuvar.py` - provjera da u repo nije ušlo ništa nešifrirano (pokreće se sama na GitHubu)
- `relej/` - relej za Daljinski pristup (vidi niže)

## Ručna objava paketa

```
pip install cryptography
export PREUZMI_LOZINKA='...'          # nikad u datoteku
python alati/paket.py popis
python alati/paket.py objavi --id knjige --naziv "Narudžbe knjiga" \
    --zip Narudzbe-knjiga.zip --datoteka Narudzbe-knjiga.zip --verzija 2026.11.12
python alati/paket.py provjeri
```

## Daljinski pristup

- Instalacija: https://raw.githubusercontent.com/giljevicivan-gif/preuzmi/main/daljinski/Daljinski_Setup.exe
  (bez administratora, u %LOCALAPPDATA%\Programs\DaljinskiPristup, prečac na radnoj površini, uklanjanje preko Postavki sustava)
- `Daljinski.zip` - isti program bez instalacije; iz njega se programi ažuriraju
- `daljinski/verzija.json` - instalirani programi ovdje provjeravaju ima li nove verzije i sami se ažuriraju.
  Za novu verziju zamijeni `Daljinski.zip` i u `verzija.json` upiši novu verziju i `zip_sha256`.

## Relej (Daljinski pristup)

Na Linux serveru (Ubuntu/Debian), jedna naredba (ista naredba i za nadogradnju):

    curl -fsSL https://raw.githubusercontent.com/giljevicivan-gif/preuzmi/main/relej/postavi.sh | sudo bash
