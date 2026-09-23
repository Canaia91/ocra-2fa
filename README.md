# OCRA 2FA PWA v4

Correzioni principali:
- Salvataggio token funzionante e aggiornamento immediato della selezione.
- Mostra/Nascondi secret funzionante.
- Layout in 3 riquadri:
  1. Configurazione e salvataggio token.
  2. Selezione ed eliminazione token.
  3. Challenge e generatore OCRA.
- Cache PWA aggiornata alla versione v4.
- Migrazione automatica dei token eventualmente salvati nelle versioni v2/v3.
- Suite supportate:
  - OCRA-1:HOTP-SHA1-6:QN08
  - OCRA-1:HOTP-SHA1-7:QN08
  - OCRA-1:HOTP-SHA1-8:QN08

Test RFC:
Secret HEX: 3132333435363738393031323334353637383930
Challenge: 00000000
Risultato atteso: 237653
