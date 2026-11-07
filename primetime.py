#!/usr/bin/env python3
# ============================================================
#  primeTime - Krypto-Helfer für CTF-Aufgaben (RSA & Diffie-Hellman)
#  Starten mit:  python3 primetime.py
# ============================================================

import json
import random
import time
import urllib.error
import urllib.request
from math import gcd, isqrt   # gcd = "größter gemeinsamer Teiler"


# ------------------------------------------------------------
#  Hilfsfunktion: Fragt eine Zahl ab.
#  Wenn man nur Enter drückt, kommt None (= "weiß ich nicht") zurück.
# ------------------------------------------------------------
def zahl_abfragen(text, pflicht=True):
    while True:
        eingabe = input(text).strip()
        if eingabe == "" and not pflicht:
            return None
        try:
            # Zahlen mit 0x am Anfang werden als Hex gelesen
            if eingabe.lower().startswith("0x"):
                return int(eingabe, 16)
            return int(eingabe)
        except ValueError:
            print("  ⚠  Bitte eine ganze Zahl eingeben (dezimal oder mit 0x als Hex).")


# ============================================================
#  FAKTORISIEREN
# ============================================================
def ist_prim(n):
    # Miller-Rabin-Test: bei großen Zahlen "mit extrem hoher Sicherheit prim"
    if n < 2:
        return False
    basen = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]
    for b in basen:
        if n % b == 0:
            return n == b
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for a in basen:
        x = pow(a, s, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def fermat(n, ende, max_schritte=1_000_000):
    # Findet Teiler schnell, wenn p und q sehr nah beieinander liegen
    a = isqrt(n)
    if a * a < n:
        a += 1
    for i in range(max_schritte):
        if i % 4096 == 0 and time.monotonic() >= ende:
            return None
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            teiler = a - b
            return teiler if 1 < teiler < n else None
        a += 1
    return None


def pollard_rho(n, ende):
    # Findet Teiler schnell, wenn einer der Primfaktoren klein genug ist
    while time.monotonic() < ende:
        y = random.randrange(1, n)
        c = random.randrange(1, n)
        schritt = 256
        g = r = q = 1
        x = ys = y
        while g == 1:
            x = y
            for i in range(r):
                if i % 65536 == 0 and time.monotonic() >= ende:
                    return None
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                if time.monotonic() >= ende:
                    return None
                ys = y
                for _ in range(min(schritt, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = gcd(q, n)
                k += schritt
            r *= 2
        if g == n:
            # Zu viel auf einmal zusammengefasst: einzeln nachrechnen
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = gcd(abs(x - ys), n)
        if g != n:
            return g
    return None


def faktorisieren_lokal(n, zeitlimit=20):
    # Gibt {Primfaktor: Anzahl} und die Liste der ungelösten Reste zurück
    ende = time.monotonic() + zeitlimit
    faktoren = {}
    offen = []

    # Kleine Primfaktoren direkt abziehen
    for t in range(2, 10_000):
        while n % t == 0 and n > 1:
            faktoren[t] = faktoren.get(t, 0) + 1
            n //= t

    stapel = [n]
    while stapel:
        m = stapel.pop()
        if m == 1:
            continue
        if ist_prim(m):
            faktoren[m] = faktoren.get(m, 0) + 1
            continue
        teiler = fermat(m, ende) or pollard_rho(m, ende)
        if teiler is None:
            offen.append(m)
        else:
            stapel += [teiler, m // teiler]
    return faktoren, offen


def factordb_abfragen(n):
    # Fragt factordb.com nach bekannten Faktoren. Gibt {Faktor: Anzahl} zurück,
    # oder None, wenn die Abfrage scheitert oder die Antwort nicht zu n passt.
    url = f"https://factordb.com/api?query={n}"
    anfrage = urllib.request.Request(url, headers={"User-Agent": "primeTime"})
    try:
        with urllib.request.urlopen(anfrage, timeout=20) as antwort:
            daten = json.load(antwort)
        ergebnis = {int(f): int(anzahl) for f, anzahl in daten["factors"]}
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as fehler:
        print(f"  ⚠  factordb-Abfrage fehlgeschlagen: {fehler}")
        return None

    # Der Antwort nicht blind vertrauen: Das Produkt muss wieder n ergeben
    produkt = 1
    for f, anzahl in ergebnis.items():
        produkt *= f ** anzahl
    if produkt != n:
        print("  ⚠  factordb-Antwort passt nicht zu n und wird ignoriert.")
        return None
    return ergebnis


def faktoren_finden(n):
    # Erst lokal rechnen, danach nur auf Nachfrage factordb.com verwenden
    print("  Suche Faktoren lokal (bis zu 20 Sekunden) ...")
    faktoren, offen = faktorisieren_lokal(n)

    if offen:
        print("  Lokal nicht vollständig faktorisiert.")
        frage = "  n an factordb.com senden und dort nachsehen? (j/N): "
        if input(frage).strip().lower() in ("j", "ja", "y", "yes"):
            noch_offen = []
            for rest in offen:
                ergebnis = factordb_abfragen(rest)
                if ergebnis is None:
                    noch_offen.append(rest)
                    continue
                for f, anzahl in ergebnis.items():
                    if ist_prim(f):
                        faktoren[f] = faktoren.get(f, 0) + anzahl
                    else:
                        noch_offen += [f] * anzahl
            offen = noch_offen
    return faktoren, offen


def phi_aus_faktoren(faktoren):
    # Funktioniert auch bei p = q und bei mehr als zwei Primfaktoren
    phi = 1
    for p, anzahl in faktoren.items():
        phi *= p ** (anzahl - 1) * (p - 1)
    return phi


def faktoren_anzeigen(n, faktoren, offen):
    print(f"\n  n = {n}")
    for p in sorted(faktoren):
        zusatz = f" (kommt {faktoren[p]}-mal vor)" if faktoren[p] > 1 else ""
        print(f"  Primfaktor: {p}{zusatz}")
    for rest in offen:
        print(f"  ⚠  Nicht faktorisiert: {rest}")


def zahl_als_text(zahl):
    # Wandelt die entschlüsselte Zahl in Bytes und, wenn möglich, in Text um
    roh = zahl.to_bytes((zahl.bit_length() + 7) // 8 or 1, "big")
    try:
        text = roh.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


def ctf_entschluesseln():
    # Der typische CTF-Fall: Gegeben sind nur n, e und c
    n = zahl_abfragen("n = ")
    e = zahl_abfragen("e = ")
    c = zahl_abfragen("Ciphertext c = ")
    if n < 2 or e < 1:
        print("  ⚠  n muss größer als 1 und e mindestens 1 sein.")
        return

    faktoren, offen = faktoren_finden(n)
    faktoren_anzeigen(n, faktoren, offen)
    if offen:
        print("\n  Ohne alle Primfaktoren lässt sich d nicht berechnen.")
        return

    phi = phi_aus_faktoren(faktoren)
    d = d_berechnen(e, phi)
    if d is None:
        return
    m = pow(c, d, n)
    print(f"\n  ϕ(n) = {phi}")
    print(f"  d    = {d}")
    print(f"  m    = {m}")
    print(f"  Hex  = {m:#x}")
    text = zahl_als_text(m)
    if text is not None:
        print(f"  Text = {text}")
    else:
        print("  Text = (kein lesbarer Text)")


# ============================================================
#  RSA
# ============================================================
def rsa_menue():
    print("\n--- RSA ---")
    print("1) n und ϕ(n) aus p und q berechnen")
    print("2) d (Private Key) berechnen")
    print("3) Verschlüsseln   (y = x^e mod n)")
    print("4) Entschlüsseln   (x = y^d mod n)")
    print("5) Alles auf einmal (p, q, e eingeben)")
    print("6) n faktorisieren  (p und q finden)")
    print("7) CTF-Modus        (nur n, e, c gegeben → Klartext)")
    wahl = input("Auswahl: ").strip()

    if wahl == "1":
        p = zahl_abfragen("p = ")
        q = zahl_abfragen("q = ")
        n = p * q
        phi = (p - 1) * (q - 1)
        print(f"\n  n    = p × q             = {p} × {q} = {n}")
        print(f"  ϕ(n) = (p - 1) × (q - 1) = {p-1} × {q-1} = {phi}")

    elif wahl == "2":
        print("Gib ϕ(n) direkt ein ODER drück Enter, dann frage ich p und q ab.")
        phi = zahl_abfragen("ϕ(n) = ", pflicht=False)
        if phi is None:
            p = zahl_abfragen("p = ")
            q = zahl_abfragen("q = ")
            phi = (p - 1) * (q - 1)
            print(f"  → ϕ(n) = {phi}")
        e = zahl_abfragen("e = ")
        d = d_berechnen(e, phi)
        if d is not None:
            print(f"\n  d = {d}")
            print(f"  Probe: ({e} × {d}) mod {phi} = {(e * d) % phi}")

    elif wahl == "3":
        x = zahl_abfragen("Klartext x = ")
        e = zahl_abfragen("e = ")
        n = zahl_abfragen("n = ")
        print(f"\n  y = {x}^{e} mod {n} = {pow(x, e, n)}")

    elif wahl == "4":
        y = zahl_abfragen("Ciphertext y = ")
        d = zahl_abfragen("d = ")
        n = zahl_abfragen("n = ")
        print(f"\n  x = {y}^{d} mod {n} = {pow(y, d, n)}")

    elif wahl == "5":
        p = zahl_abfragen("p = ")
        q = zahl_abfragen("q = ")
        e = zahl_abfragen("e = ")
        n = p * q
        phi = (p - 1) * (q - 1)
        print(f"\n  n    = {n}")
        print(f"  ϕ(n) = {phi}")
        d = d_berechnen(e, phi)
        if d is None:
            return
        print(f"  d    = {d}")
        print(f"  Public Key  (n, e) = ({n}, {e})")
        print(f"  Private Key (n, d) = ({n}, {d})")
        x = zahl_abfragen("\nOptional: Zahl zum Verschlüsseln (Enter = überspringen): ",
                          pflicht=False)
        if x is not None:
            y = pow(x, e, n)
            print(f"  Verschlüsselt: {x}^{e} mod {n} = {y}")
            print(f"  Entschlüsselt: {y}^{d} mod {n} = {pow(y, d, n)}")

    elif wahl == "6":
        n = zahl_abfragen("n = ")
        if n < 2:
            print("  ⚠  n muss größer als 1 sein.")
            return
        faktoren, offen = faktoren_finden(n)
        faktoren_anzeigen(n, faktoren, offen)

    elif wahl == "7":
        ctf_entschluesseln()

    else:
        print("Ungültige Auswahl.")


def d_berechnen(e, phi):
    # e und ϕ(n) müssen teilerfremd sein, sonst gibt es kein d
    if gcd(e, phi) != 1:
        print(f"  ⚠  e = {e} und ϕ(n) = {phi} sind NICHT teilerfremd "
              f"(gemeinsamer Teiler: {gcd(e, phi)}). Kein d möglich.")
        return None
    # pow(e, -1, phi) berechnet das "modulare Inverse"
    return pow(e, -1, phi)


# ============================================================
#  DIFFIE-HELLMAN
# ============================================================
def dh_menue():
    print("\n--- Diffie-Hellman ---")
    print("1) Public Key berechnen     (A = g^a mod p)")
    print("2) Gemeinsames Geheimnis    (B^a mod p)")
    print("3) Alles auf einmal (p, g, a, b eingeben)")
    wahl = input("Auswahl: ").strip()

    if wahl == "1":
        p = zahl_abfragen("p = ")
        g = zahl_abfragen("g = ")
        a = zahl_abfragen("Private Key (a oder b) = ")
        print(f"\n  Public Key = {g}^{a} mod {p} = {pow(g, a, p)}")

    elif wahl == "2":
        p = zahl_abfragen("p = ")
        andere = zahl_abfragen("Public Key der ANDEREN Person (A oder B) = ")
        eigen = zahl_abfragen("Eigener Private Key (a oder b) = ")
        print(f"\n  Geheimnis = {andere}^{eigen} mod {p} = {pow(andere, eigen, p)}")

    elif wahl == "3":
        p = zahl_abfragen("p = ")
        g = zahl_abfragen("g = ")
        a = zahl_abfragen("a (Alice geheim) = ")
        b = zahl_abfragen("b (Bob geheim)   = ")
        A = pow(g, a, p)
        B = pow(g, b, p)
        s_alice = pow(B, a, p)
        s_bob = pow(A, b, p)
        print(f"\n  A = {g}^{a} mod {p} = {A}")
        print(f"  B = {g}^{b} mod {p} = {B}")
        print(f"  Alice rechnet: B^a mod p = {B}^{a} mod {p} = {s_alice}")
        print(f"  Bob rechnet:   A^b mod p = {A}^{b} mod {p} = {s_bob}")
        if s_alice == s_bob:
            print(f"  ✅ Gemeinsames Geheimnis = {s_alice}")
    else:
        print("Ungültige Auswahl.")


# ============================================================
#  HAUPTMENÜ
# ============================================================
def main():
    while True:
        print("\n==============================")
        print("   🔐 primeTime")
        print("==============================")
        print("1) RSA")
        print("2) Diffie-Hellman")
        print("0) Beenden")
        wahl = input("Welche Verschlüsselung? ").strip()

        if wahl == "1":
            rsa_menue()
        elif wahl == "2":
            dh_menue()
        elif wahl == "0":
            print("Tschüss! 🍵")
            break
        else:
            print("Ungültige Auswahl.")


# Startet main(), wenn die Datei direkt ausgeführt wird
if __name__ == "__main__":
    main()
