#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Relej posluzitelj za "Daljinski pristup" (nas vlastiti AnyDesk/TeamViewer posrednik).

Sto radi:
  * racunala koja dijele ekran prijave se sa svojim ID-om (9 znamenki)
  * kad se netko spaja po ID-u, relej spoji ta dva racunala i samo prosljeduje bajtove
  * sav promet je sifriran s kraja na kraj (AES-256) lozinkom koju relej NE zna,
    pa relej ne moze vidjeti ekran ni datoteke

Pokretanje:   python relej_server.py            (port 50510)
              python relej_server.py --port 6000
              python relej_server.py --admin-lozinka NEKA_JAKA_LOZINKA
                 (ili lozinka u prvom redu datoteke relej_admin.txt pored ovog programa)
                 -> u programu kartica "Instalacije" pokazuje sva racunala koja se javljaju releju
Potrebno:     samo Python 3.8+ (bez dodatnih paketa)
              (ili bez Pythona: Daljinski.exe --relej [--port N] [--admin-lozinka X])

Na routeru / vatrozidu treba otvoriti TCP port (zadano 50510) prema ovom racunalu.
"""
import argparse
import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import time

ZADANI_PORT = 50510
if os.environ.get("RELEJ_MAPA"):
    MAPA = os.environ["RELEJ_MAPA"]
elif getattr(sys, "frozen", False):      # pokrenut iz Daljinski.exe --relej
    MAPA = os.path.join(os.environ.get("PROGRAMDATA") or os.path.expanduser("~"), "DaljinskiRelej")
else:
    MAPA = os.path.dirname(os.path.abspath(__file__))
os.makedirs(MAPA, exist_ok=True)
REGISTAR = os.path.join(MAPA, "relej_registar.json")
INSTALACIJE = os.path.join(MAPA, "relej_instalacije.json")
ADMIN_DATOTEKA = os.path.join(MAPA, "relej_admin.txt")
DNEVNIK_SPAJANJA = os.path.join(MAPA, "relej_dnevnik.jsonl")
NAJVISE_ZAPISA = 5000

hostovi = {}     # id -> StreamWriter kontrolne veze
cekanje = {}     # token -> Future
registar = {}    # id -> sha256(tajna) - da nitko ne moze "ukrasti" tudi ID
pokusaji = {}    # ip -> vremena pokusaja spajanja
instalacije = {}  # id -> {naziv, ver, os, mac, ip, prvi, zadnji, ...} - za pregled (kartica Instalacije)
admin_hash = None
promjena = [False]
zapisi = []      # dnevnik spajanja (tko se kada spajao) - javljaju ga racunala


def dnevnik(poruka):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), poruka, flush=True)


def ucitaj_registar():
    global registar
    try:
        with open(REGISTAR, "r", encoding="utf-8") as f:
            registar = json.load(f)
    except Exception:
        registar = {}


def ucitaj_instalacije():
    global instalacije
    try:
        with open(INSTALACIJE, "r", encoding="utf-8") as f:
            instalacije = json.load(f)
    except Exception:
        instalacije = {}


def spremi_instalacije():
    try:
        with open(INSTALACIJE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(instalacije, f, ensure_ascii=False, indent=1)
        os.replace(INSTALACIJE + ".tmp", INSTALACIJE)
        promjena[0] = False
    except Exception as e:
        dnevnik("Ne mogu spremiti instalacije: %s" % e)


def ucitaj_zapise():
    global zapisi
    zapisi = []
    try:
        with open(DNEVNIK_SPAJANJA, "r", encoding="utf-8") as f:
            for red in f:
                try:
                    zapisi.append(json.loads(red))
                except Exception:
                    pass
    except OSError:
        pass
    zapisi = zapisi[-NAJVISE_ZAPISA:]


def dodaj_zapis(z):
    zapisi.append(z)
    try:
        if len(zapisi) > NAJVISE_ZAPISA + 500:      # povremeno skrati datoteku
            del zapisi[:len(zapisi) - NAJVISE_ZAPISA]
            with open(DNEVNIK_SPAJANJA + ".tmp", "w", encoding="utf-8") as f:
                for x in zapisi:
                    f.write(json.dumps(x, ensure_ascii=False) + "\n")
            os.replace(DNEVNIK_SPAJANJA + ".tmp", DNEVNIK_SPAJANJA)
        else:
            with open(DNEVNIK_SPAJANJA, "a", encoding="utf-8") as f:
                f.write(json.dumps(z, ensure_ascii=False) + "\n")
    except Exception as e:
        dnevnik("Ne mogu spremiti dnevnik spajanja: %s" % e)


async def spremanje_petlja():
    while True:
        await asyncio.sleep(60)
        if promjena[0]:
            spremi_instalacije()


def admin_ok(lozinka, ip):
    """Provjera admin lozinke (s ogranicenjem pokusaja po IP-u)."""
    if not admin_hash:
        return False, "Na releju nije postavljena admin lozinka (pokreni relej s --admin-lozinka ili napravi relej_admin.txt)."
    sad = time.time()
    lista = [x for x in pokusaji.get("admin:" + ip, []) if sad - x < 300]
    if len(lista) >= 10:
        return False, "Previše krivih pokušaja, pričekaj 5 minuta."
    if hmac.compare_digest(hashlib.sha256(str(lozinka).encode("utf-8")).hexdigest(), admin_hash):
        return True, ""
    lista.append(sad)
    pokusaji["admin:" + ip] = lista
    return False, "Kriva admin lozinka."


def spremi_registar():
    try:
        with open(REGISTAR, "w", encoding="utf-8") as f:
            json.dump(registar, f, indent=1)
    except Exception as e:
        dnevnik("Ne mogu spremiti registar: %s" % e)


def posalji(w, d):
    try:
        w.write((json.dumps(d, ensure_ascii=False) + "\n").encode("utf-8"))
    except Exception:
        pass


def zatvori(w):
    try:
        w.close()
    except Exception:
        pass


async def cijev(r, w):
    try:
        while True:
            podaci = await r.read(262144)
            if not podaci:
                break
            w.write(podaci)
            await w.drain()
    except (ConnectionError, OSError, asyncio.IncompleteReadError):
        pass
    finally:
        zatvori(w)


async def obradi(r, w):
    ip = (w.get_extra_info("peername") or ("?",))[0]
    s = w.get_extra_info("socket")
    if s is not None:   # bez Nagleovog kasnjenja: mis i tipkovnica stizu odmah
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
    w.transport.set_write_buffer_limits(high=1024 * 1024)
    try:
        linija = await asyncio.wait_for(r.readline(), 15)
        m = json.loads(linija.decode("utf-8"))
    except Exception:
        zatvori(w)
        return
    t = m.get("t")
    if t == "reg":
        await registracija(r, w, m, ip)
    elif t == "conn":
        await spajanje(r, w, m, ip)
    elif t == "status":
        idovi = [str(x) for x in m.get("ids", [])][:300]
        posalji(w, {"t": "status", "online": [i for i in idovi if i in hostovi]})
        try:
            await w.drain()
        except Exception:
            pass
        zatvori(w)
    elif t == "popis":
        ok, poruka = admin_ok(m.get("lozinka", ""), ip)
        if ok:
            popis = []
            for i, d in instalacije.items():
                popis.append(dict(d, id=i, online=i in hostovi))
            posalji(w, {"t": "popis", "instalacije": popis, "sad": int(time.time())})
        else:
            posalji(w, {"t": "err", "poruka": poruka})
        await zavrsi(w)
    elif t == "dnevnik":
        ok, poruka = admin_ok(m.get("lozinka", ""), ip)
        if ok:
            hid = str(m.get("id", "") or "")
            lista = [z for z in zapisi if not hid or z.get("id") == hid]
            posalji(w, {"t": "dnevnik", "zapisi": lista[-int(m.get("koliko", 500) or 500):]})
        else:
            posalji(w, {"t": "err", "poruka": poruka})
        await zavrsi(w)
    elif t == "zaboravi":
        ok, poruka = admin_ok(m.get("lozinka", ""), ip)
        if ok:
            instalacije.pop(str(m.get("id", "")), None)
            spremi_instalacije()
            posalji(w, {"t": "ok"})
        else:
            posalji(w, {"t": "err", "poruka": poruka})
        await zavrsi(w)
    elif t == "wol":
        await wol(w, m, ip)
    elif t == "data":
        fut = cekanje.pop(str(m.get("token", "")), None)
        if fut is not None and not fut.done():
            gotovo = asyncio.Event()
            fut.set_result((r, w, gotovo))
            await gotovo.wait()
        else:
            zatvori(w)
    else:
        zatvori(w)


async def zavrsi(w):
    try:
        await w.drain()
    except Exception:
        pass
    zatvori(w)


async def wol(w, m, ip):
    """Probudi racunalo: zamoli neko online racunalo s iste javne IP adrese (ista lokalna mreza)
    da posalje Wake-on-LAN paket."""
    hid = str(m.get("id", "")).replace(" ", "")
    d = instalacije.get(hid)
    mac = (d or {}).get("mac") or str(m.get("mac", ""))
    if not d:
        posalji(w, {"t": "err", "poruka": "Relej ne poznaje računalo %s." % hid})
    elif hid in hostovi:
        posalji(w, {"t": "ok", "poruka": "Računalo je već upaljeno (na mreži)."})
    elif not mac:
        posalji(w, {"t": "err", "poruka": "Relej ne zna MAC adresu tog računala."})
    else:
        pomagaci = [i for i, x in instalacije.items() if i in hostovi and x.get("ip") == d.get("ip")]
        for i in pomagaci[:3]:
            posalji(hostovi[i], {"t": "wol", "mac": mac})
        if pomagaci:
            posalji(w, {"t": "ok", "poruka": "Relej je zamolio %d računalo/a iz iste mreže da ga probude." % len(pomagaci)})
            dnevnik("WOL %s preko %s (zatražio %s)" % (hid, ", ".join(pomagaci[:3]), ip))
        else:
            posalji(w, {"t": "err", "poruka": "U mreži tog računala nijedno drugo računalo s programom nije upaljeno, "
                                              "pa ga relej ne može probuditi preko interneta."})
    await zavrsi(w)


async def registracija(r, w, m, ip):
    hid = str(m.get("id", ""))
    tajna = str(m.get("tajna", ""))
    if not re.fullmatch(r"[1-9]\d{8}", hid) or len(tajna) < 16:
        posalji(w, {"t": "err", "poruka": "Neispravan ID."})
        zatvori(w)
        return
    h = hashlib.sha256(tajna.encode("utf-8")).hexdigest()
    if hid in registar and registar[hid] != h:
        posalji(w, {"t": "err", "poruka": "Taj ID već koristi drugo računalo."})
        zatvori(w)
        return
    if hid not in registar:
        registar[hid] = h
        spremi_registar()
    stari = hostovi.get(hid)
    if stari is not None and stari is not w:
        zatvori(stari)
    hostovi[hid] = w
    info = m.get("info") if isinstance(m.get("info"), dict) else {}
    staro = instalacije.get(hid, {})
    zapis = {k: str(info.get(k, staro.get(k, "")))[:120] for k in ("naziv", "ver", "os", "mac", "korisnik")}
    zapis.update({k: bool(info.get(k, staro.get(k, False))) for k in ("servis", "podrska", "stalna")})
    zapis.update({"ip": ip, "prvi": staro.get("prvi", int(time.time())), "zadnji": int(time.time())})
    if not info:
        zapis["ver"] = staro.get("ver") or "4.1 ili starija"
    instalacije[hid] = zapis
    spremi_instalacije()
    posalji(w, {"t": "ok"})
    dnevnik("Prijavljen ID %s s %s (online: %d)" % (hid, ip, len(hostovi)))
    try:
        while True:
            linija = await asyncio.wait_for(r.readline(), 90)
            if not linija:
                break
            try:
                mm = json.loads(linija.decode("utf-8"))
            except Exception:
                continue
            if mm.get("t") == "zapis":
                z = {k: str(mm.get(k, ""))[:200] for k in ("dogadjaj", "tko", "vrsta", "izvor")}
                z.update({"id": hid, "naziv": instalacije.get(hid, {}).get("naziv", ""), "vrijeme": int(time.time()),
                          "trajanje": int(mm.get("trajanje", 0) or 0)})
                dodaj_zapis(z)
            elif mm.get("t") == "ping":
                posalji(w, {"t": "pong"})
                if hid in instalacije:
                    instalacije[hid]["zadnji"] = int(time.time())
                    promjena[0] = True
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        if hostovi.get(hid) is w:
            del hostovi[hid]
            if hid in instalacije:
                instalacije[hid]["zadnji"] = int(time.time())
                promjena[0] = True
            dnevnik("Odjavljen ID %s" % hid)
        zatvori(w)


async def spajanje(r, w, m, ip):
    sad = time.time()
    lista = [x for x in pokusaji.get(ip, []) if sad - x < 60]
    lista.append(sad)
    pokusaji[ip] = lista
    if len(lista) > 20:
        posalji(w, {"t": "err", "poruka": "Previše pokušaja, pričekaj minutu."})
        zatvori(w)
        return
    hid = str(m.get("id", "")).replace(" ", "")
    hw = hostovi.get(hid)
    if hw is None:
        posalji(w, {"t": "err", "poruka": "Računalo s ID-om %s nije na mreži." % hid})
        zatvori(w)
        return
    token = secrets.token_hex(16)
    fut = asyncio.get_running_loop().create_future()
    cekanje[token] = fut
    posalji(hw, {"t": "poziv", "token": token})
    try:
        hr, hw2, gotovo = await asyncio.wait_for(fut, 15)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        cekanje.pop(token, None)
        posalji(w, {"t": "err", "poruka": "Računalo se ne javlja."})
        zatvori(w)
        return
    posalji(w, {"t": "ok"})
    dnevnik("Sesija: %s -> ID %s" % (ip, hid))
    t0 = time.time()
    await asyncio.gather(cijev(r, hw2), cijev(hr, w))
    gotovo.set()
    dnevnik("Kraj sesije %s -> ID %s (%d min)" % (ip, hid, (time.time() - t0) // 60))


async def glavna(port):
    ucitaj_registar()
    ucitaj_instalacije()
    ucitaj_zapise()
    asyncio.create_task(spremanje_petlja())
    dnevnik("Pregled instalacija: %s" % ("uključen (admin lozinka postavljena)" if admin_hash
                                         else "admin lozinka NIJE postavljena (--admin-lozinka)"))
    srv = await asyncio.start_server(obradi, "0.0.0.0", port)
    dnevnik("Relej radi na portu %d. Za prekid pritisni Ctrl+C." % port)
    async with srv:
        await srv.serve_forever()


def main(argv=None):
    global admin_hash
    ap = argparse.ArgumentParser(description="Relej posluzitelj za Daljinski pristup")
    ap.add_argument("--port", type=int, default=ZADANI_PORT)
    ap.add_argument("--admin-lozinka", default=os.environ.get("RELEJ_ADMIN_LOZINKA", ""),
                    help="lozinka za pregled instalacija (kartica Instalacije u programu)")
    a = ap.parse_args(argv)
    loz = a.admin_lozinka
    if not loz and os.path.exists(ADMIN_DATOTEKA):
        with open(ADMIN_DATOTEKA, "r", encoding="utf-8") as f:
            loz = f.readline().strip()
    if loz:
        admin_hash = hashlib.sha256(loz.encode("utf-8")).hexdigest()
    try:
        asyncio.run(glavna(a.port))
    except KeyboardInterrupt:
        dnevnik("Relej zaustavljen.")


if __name__ == "__main__":
    main()
