# primeTime

Kleiner Krypto-Helfer für die Kommandozeile, gedacht für CTF-Aufgaben (z. B. auf TryHackMe). Er rechnet die gängigen Schritte von RSA und Diffie-Hellman aus und zeigt dabei den Rechenweg.

## Starten

Benötigt Python 3.8 oder neuer, sonst nichts.

```bash
python3 primetime.py
```

## Funktionen

**RSA**

- `n` und `ϕ(n)` aus `p` und `q` berechnen
- Private Key `d` berechnen, aus `ϕ(n)` oder aus `p` und `q`
- Verschlüsseln (`y = x^e mod n`) und entschlüsseln (`x = y^d mod n`)
- Alles auf einmal aus `p`, `q` und `e`
- `n` faktorisieren
- CTF-Modus: aus `n`, `e` und `c` direkt den Klartext berechnen, als Zahl, Hex und Text

Zahlen können dezimal oder mit `0x` als Hex eingegeben werden.

**Diffie-Hellman**

- Public Key berechnen (`A = g^a mod p`)
- Gemeinsames Geheimnis berechnen (`B^a mod p`)
- Alles auf einmal aus `p`, `g`, `a` und `b`

## Faktorisieren

Das Tool rechnet zuerst bis zu 20 Sekunden lokal:

- Probedivision für kleine Primfaktoren
- Fermat, wenn `p` und `q` nah beieinander liegen
- Pollard-Rho, wenn ein Primfaktor klein genug ist

Klappt das nicht, fragt es nach, ob `n` an [factordb.com](https://factordb.com) gesendet werden soll. Ohne deine Zustimmung verlässt nichts den Rechner. Die Antwort wird geprüft: Das Produkt der Faktoren muss wieder `n` ergeben.

## Grenzen

Ein starkes RSA-`n` lässt sich nicht faktorisieren, außer die Faktoren sind bereits in factordb eingetragen. Andere RSA-Angriffe wie Wiener oder kleine `e` sind nicht eingebaut, und diskrete Logarithmen für Diffie-Hellman löst das Tool auch nicht.
