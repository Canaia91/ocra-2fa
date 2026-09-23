# OCRA 2FA PWA

Web app installabile su iPhone/Windows senza Xcode e senza Apple Developer.

## Suite supportata
OCRA-1:HOTP-SHA1-6:QN08

- HMAC-SHA1
- risposta a 6 cifre
- challenge numerica da 1 a 8 cifre
- nessun timer
- nessun counter
- nessun PIN

## Test RFC 6287
Secret HEX:
3132333435363738393031323334353637383930

Challenge:
00000000

Risultato atteso:
237653

## Pubblicazione
La PWA deve essere servita da HTTPS per l'installazione e il funzionamento offline del service worker.
Puoi pubblicare gratuitamente la cartella con GitHub Pages, Cloudflare Pages, Netlify o un normale hosting HTTPS.

Su iPhone:
1. Apri l'indirizzo in Safari.
2. Tocca Condividi.
3. Tocca "Aggiungi alla schermata Home".
4. Aprila dall'icona creata.

## Sicurezza
Il calcolo è interamente locale. Nessun secret viene inviato a un server.
Se attivi "Salva ... secret", il secret viene salvato nel localStorage del browser/PWA:
non equivale al Keychain iOS. Se vuoi massima protezione, lascia disattivato il salvataggio del secret.

Nota: per QN08 la challenge numerica viene trattata secondo il codice di riferimento RFC 6287 (decimale → Base16 → padding a destra del campo Q a 128 byte).

## Versione multi-token
Puoi salvare più token/macchine, ciascuno con nome, formato secret, suite e secret. Li selezioni dal menu in alto.
I secret salvati restano nel localStorage del browser/PWA e non nel Keychain iOS.

## Layout v3
L'interfaccia è divisa in tre riquadri:
1. Configurazione token: nome, secret, formato, cifre, OCRA Suite e Salva.
2. Selezione token: scelta del token salvato e pulsante Elimina.
3. Generatore: challenge e pulsante Genera OCRA.

Sono supportate le suite:
- OCRA-1:HOTP-SHA1-6:QN08
- OCRA-1:HOTP-SHA1-7:QN08
- OCRA-1:HOTP-SHA1-8:QN08
