# Preuzimanje

Stranica: https://giljevicivan-gif.github.io/preuzmi/

Datoteka scan.bin je sifrirana (AES-256-GCM, lozinka). Izvorne skripte su u privatnom repou scan-folder-setup.

## Daljinski pristup

- Instalacija: https://raw.githubusercontent.com/giljevicivan-gif/preuzmi/main/daljinski/Daljinski_Setup.exe
  (bez administratora, u %LOCALAPPDATA%\Programs\DaljinskiPristup, prečac na radnoj površini, uklanjanje preko Postavki sustava)
- `Daljinski.zip` - isti program bez instalacije; iz njega se programi ažuriraju
- `daljinski/verzija.json` - instalirani programi ovdje provjeravaju ima li nove verzije i sami se ažuriraju.
  Za novu verziju zamijeni `Daljinski.zip` i u `verzija.json` upiši novu verziju i `zip_sha256`.
