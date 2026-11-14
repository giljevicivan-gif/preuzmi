#!/usr/bin/env python3
"""Cuvar javnog repozitorija: pada ako bi se objavilo nesto sto ne smije biti javno.

Pokrece se automatski na GitHubu (.github/workflows/cuvar.yml) kod svake promjene.
"""
import fnmatch
import subprocess
import sys

ZABRANJENO = ['*.db', '*.db-wal', '*.db-shm', '*.sqlite', '*.sqlite3', '*.mdb', '*.accdb',
              '*PODACI-ZA-UREDJAJ*', 'Racunala.txt', '*.log', '*.pfx', '*.pem', '*.key', '.env',
              'postavke.json', 'sigurnosne_kopije/*']
# Nesifrirani ZIP/EXE smiju biti samo ovdje (Daljinski pristup je javan po dogovoru).
JAVNE_MAPE = ('daljinski/',)

greske = []
datoteke = subprocess.run(['git', 'ls-files', '-z'], capture_output=True, check=True).stdout.decode().split('\0')
for f in filter(None, datoteke):
    ime = f.rsplit('/', 1)[-1]
    if any(fnmatch.fnmatch(ime, z) or fnmatch.fnmatch(f, z) for z in ZABRANJENO):
        greske.append('%s: ova vrsta datoteke ne smije u javni repozitorij' % f)
    if f.lower().endswith(('.zip', '.exe', '.msi', '.7z', '.rar')) and not f.startswith(JAVNE_MAPE):
        greske.append('%s: nesifrirani paket - objavi ga kao <id>.bin preko alati/paket.py' % f)
    if f.endswith('.bin'):
        with open(f, 'rb') as d:
            glava = d.read(64)
        if glava[:2] == b'PK' or glava.lstrip()[:1] in (b'[', b'{') or len(glava) < 29:
            greske.append('%s: izgleda NESIFRIRANO' % f)

html = open('index.html', encoding='utf-8').read()
if 'iterations:600000' not in html or 'AES-GCM' not in html:
    greske.append('index.html: nema sifriranja (AES-GCM / PBKDF2 600000) - stranica bi bila otvorena')

if greske:
    print('\n'.join('GRESKA: ' + g for g in greske))
    sys.exit(1)
print('OK - u repozitoriju nema nesifriranih podataka.')
