#!/usr/bin/env python3
"""Objava paketa na stranicu za preuzimanje (sifrirano).

Format svake .bin datoteke (isti kao u index.html):
    salt(16) | iv(12) | AES-256-GCM(ciphertext + tag)
    kljuc = PBKDF2-SHA256(lozinka, salt, 600000 iteracija)

paketi.bin = sifrirani JSON popis: [{"id", "naziv", "datoteka", "verzija"?, "datum"?}, ...]
<id>.bin   = sifrirani ZIP paketa.

Lozinka se NIKAD ne upisuje u kod ni na disk: cita se iz varijable PREUZMI_LOZINKA.

Naredbe (pokreni iz korijena repozitorija preuzmi):
    python alati/paket.py popis
    python alati/paket.py objavi --id skeniranje --naziv "Skeniranje u mapu" \
        --zip Skeniranje-v1.0.zip --datoteka Skeniranje.zip --verzija 1.0
    python alati/paket.py ukloni --id stari_paket
    python alati/paket.py provjeri          # svi paketi se mogu desifrirati
"""
import argparse
import datetime
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 600000
KORIJEN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POPIS = os.path.join(KORIJEN, 'paketi.bin')


def kljuc(lozinka, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(lozinka.encode())


def sifriraj(podaci, lozinka):
    salt, iv = os.urandom(16), os.urandom(12)
    return salt + iv + AESGCM(kljuc(lozinka, salt)).encrypt(iv, podaci, None)


def desifriraj(blob, lozinka):
    return AESGCM(kljuc(lozinka, blob[:16])).decrypt(blob[16:28], blob[28:], None)


def citaj(put):
    with open(put, 'rb') as f:
        return f.read()


def pisi(put, podaci):
    tmp = put + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(podaci)
    os.replace(tmp, put)


def lozinka():
    l = os.environ.get('PREUZMI_LOZINKA', '')
    if not l:
        sys.exit('Nema lozinke: postavi varijablu PREUZMI_LOZINKA.')
    return l


def ucitaj_popis(l):
    try:
        return json.loads(desifriraj(citaj(POPIS), l))
    except Exception:
        sys.exit('paketi.bin se ne moze otkljucati - kriva lozinka?')


def spremi_popis(popis, l):
    pisi(POPIS, sifriraj(json.dumps(popis, ensure_ascii=False, indent=1).encode(), l))


def cmd_popis(a):
    for p in ucitaj_popis(lozinka()):
        print('%-12s %-40s %-28s %s %s' % (p['id'], p['naziv'], p['datoteka'], p.get('verzija', '-'), p.get('datum', '')))


def cmd_objavi(a):
    l = lozinka()
    popis = ucitaj_popis(l)
    zip_bytes = citaj(a.zip)
    if zip_bytes[:2] != b'PK':
        sys.exit('%s nije ZIP.' % a.zip)
    pisi(os.path.join(KORIJEN, a.id + '.bin'), sifriraj(zip_bytes, l))
    stari = next((p for p in popis if p['id'] == a.id), None)
    novi = dict(stari or {})
    novi.update(id=a.id,
                naziv=a.naziv or (stari or {}).get('naziv') or a.id,
                datoteka=a.datoteka or (stari or {}).get('datoteka') or os.path.basename(a.zip),
                datum=datetime.date.today().isoformat())
    if a.verzija:
        novi['verzija'] = a.verzija
    if stari:
        popis[popis.index(stari)] = novi
    else:
        popis.append(novi)
    spremi_popis(popis, l)
    print('Objavljeno: %s (%s) %s, %d KB' % (novi['naziv'], novi['datoteka'], novi.get('verzija', ''), len(zip_bytes) // 1024))


def cmd_ukloni(a):
    l = lozinka()
    popis = [p for p in ucitaj_popis(l) if p['id'] != a.id]
    spremi_popis(popis, l)
    put = os.path.join(KORIJEN, a.id + '.bin')
    if os.path.exists(put):
        os.remove(put)
    print('Uklonjeno:', a.id)


def cmd_provjeri(a):
    l = lozinka()
    for p in ucitaj_popis(l):
        z = desifriraj(citaj(os.path.join(KORIJEN, p['id'] + '.bin')), l)
        print('OK %-12s %d KB' % (p['id'], len(z) // 1024))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='naredba', required=True)
    sp.add_parser('popis').set_defaults(f=cmd_popis)
    o = sp.add_parser('objavi')
    o.add_argument('--id', required=True)
    o.add_argument('--zip', required=True)
    o.add_argument('--naziv')
    o.add_argument('--datoteka', help='ime datoteke koju korisnik spremi (npr. Skeniranje.zip)')
    o.add_argument('--verzija')
    o.set_defaults(f=cmd_objavi)
    u = sp.add_parser('ukloni')
    u.add_argument('--id', required=True)
    u.set_defaults(f=cmd_ukloni)
    sp.add_parser('provjeri').set_defaults(f=cmd_provjeri)
    a = ap.parse_args()
    a.f(a)


if __name__ == '__main__':
    main()
