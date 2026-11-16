# ▲ PERSEUS

**Controllo accessi biometrico + vault di cartelle cifrate per Windows.**
Core in **Rust** (crittografia, sensori, inferenza), interfaccia **WPF / C#** in stile console operativa.

Le cartelle che scegli vengono cifrate sul posto; si decifrano solo dopo un'autenticazione riuscita.
Chi non è autorizzato riceve **NON AUTORIZZATO**.

| Fattore | Stato |
|---|---|
| Password (Argon2id) | ✅ disponibile |
| Menu tasto destro "Cifra / Decifra cartella" | ✅ disponibile |
| Camera iVCam ammessa, OBS Virtual Camera bloccata | ✅ disponibile (feed live) |
| Riconoscimento volto + anti-spoofing (foto, quadri, schermi) | 🚧 in sviluppo |
| Verifica vocale con frase casuale anti-registrazione | 🚧 in sviluppo |

---

## Installazione

1. Scarica `Perseus-<versione>-win-x64.zip` dalla pagina **[Releases](../../releases)**.
2. Estrai **tutto** lo zip in una cartella qualsiasi.
3. Doppio clic su **`install.cmd`**.

L'installazione è solo per il tuo utente e non richiede privilegi di amministratore. L'installer fa queste cose:
- copia il programma in `%LOCALAPPDATA%\Programs\Perseus`
- crea il collegamento nel menu Start
- aggiunge il menu del tasto destro sulle cartelle
- registra PERSEUS in *Impostazioni → App installate*, da dove si può disinstallare

Opzioni (da PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File install.ps1 -DesktopShortcut   # anche icona sul desktop
powershell -ExecutionPolicy Bypass -File install.ps1 -NoShellMenu       # senza menu tasto destro
```

**Requisiti:** Windows 10 o 11 a 64 bit. Il runtime .NET è già incluso nello zip.
Per il volto serve **iVCam** (app sul telefono + client PC di e2eSoft), oppure un'altra camera che aggiungi all'allowlist.

---

## Configurazione

### 1. Primo avvio: la password
Al primo avvio PERSEUS ti chiede di creare una password di almeno 8 caratteri.

> ⚠️ **La password è l'unico modo per recuperare i file.** Non esiste una chiave di recupero.
> Se la dimentichi e volto e voce non funzionano più, i file cifrati sono persi per sempre.

### 2. Scegliere le cartelle da proteggere
Ci sono due modi:
- **Dal tasto destro (consigliato):** clic destro su una cartella → **PERSEUS** → **Cifra cartella**.
  - Su Windows 11 la voce si trova in *Mostra altre opzioni* (oppure premi `Shift+F10`).
  - La cifratura **non chiede la password**, perché cifrare non espone nessun dato.
  - Per decifrare: clic destro → **PERSEUS** → **Decifra cartella (autenticazione)**. Si apre una finestrella che chiede di autenticarti: password ora, volto e voce quando saranno pronti.
- **Dall'app:** scheda **CARTELLE** → *+ AGGIUNGI CARTELLA*. Serve lo stato AUTORIZZATO.

Ogni file diventa `<id-casuale>.prs`. Il nome originale è cifrato insieme al contenuto e viene ripristinato quando decifri.

Il pulsante **BLOCCA** nella console ricifra tutte le cartelle in lista e cancella la chiave dalla memoria.

Il menu del tasto destro si attiva o disattiva anche dalla scheda **CARTELLE** (pulsante in alto a destra).

**Cartelle che PERSEUS rifiuta di cifrare**, perché il PC smetterebbe di funzionare o i file non si potrebbero più recuperare:
- `C:\Windows`, `Program Files`, `ProgramData`, `AppData`
- la radice del disco e il profilo utente intero
- la cartella del programma e la cartella dei dati di PERSEUS
- qualsiasi cartella che contiene una di queste

### 3. Camera (iVCam)
1. Installa iVCam sul telefono e il client sul PC, poi collegali (Wi-Fi o USB).
2. Avvia PERSEUS. La camera `e2eSoft iVCam` viene riconosciuta come **ATTENDIBILE** e il feed parte da solo.
3. Nella scheda **SENSORI** vedi tutte le camere con il loro verdetto:
   - **ATTENDIBILE**: è nell'allowlist e si può usare.
   - **BLOCCATA**: OBS Virtual Camera e camere virtuali simili, rifiutate sempre, anche se vengono rinominate.
   - **NON ATTENDIBILE**: non è nell'allowlist.
4. Per ammettere un'altra camera, aggiungi una parte del suo nome all'allowlist, separando i nomi con virgole, poi premi SALVA. Serve lo stato AUTORIZZATO.

### 4. Volto e voce (prossimi moduli)
Quando saranno pronti, ci sarà la scheda *Enrollment* per registrare i volti e le voci autorizzati. Il dataset conterrà solo vettori numerici (embedding), mai le foto o gli audio, e sarà salvato cifrato sul tuo PC.

---

## Dove stanno i dati

Tutti i dati personali restano **solo sul tuo PC**, in `%LOCALAPPDATA%\Perseus`. Non vengono mai caricati online e non sono in questo repository.

| File | Contenuto |
|---|---|
| `keystore.json` | chiave master cifrata (con la password e con Windows DPAPI) |
| `config.json` | cartelle protette, allowlist camere |
| `lockout.json` | contatore dei tentativi falliti |
| `journal.json` | operazione in corso, per riprendere dopo un crash |

> Non cancellare questa cartella finché hai file `.prs`: senza `keystore.json` non si possono decifrare.

## Disinstallazione
Vai in *Impostazioni → App installate → PERSEUS → Disinstalla*.

Prima di disinstallare, **decifra le cartelle**. La disinstallazione lascia i dati in `%LOCALAPPDATA%\Perseus`; per cancellarli definitivamente usa `uninstall.ps1 -PurgeData`.

---

## Sicurezza: come funziona e limiti

**Come funziona:**
- **Cifratura:** XChaCha20-Poly1305 in modalità STREAM, a blocchi da 1 MiB. Ogni file ha la sua chiave, derivata con HKDF-SHA256. Qualsiasi modifica o troncamento del file viene rilevato.
- **Scrittura sicura:**
  1. scrive un file temporaneo
  2. fa flush su disco
  3. lo verifica decifrandolo
  4. lo rinomina in modo atomico
  5. sovrascrive e cancella l'originale

  Un journal permette di riprendere dopo un crash.
- **Password:** Argon2id (256 MiB, 3 passaggi). Dopo 3 errori il blocco cresce: 5 s, 10 s, 20 s, … fino a 15 minuti, e resta anche se riavvii l'app.

**Limiti:**
- **Sblocco con un solo fattore.** Basta uno qualsiasi tra volto, voce e password. Per questo la chiave per la biometria è protetta da DPAPI, cioè legata al tuo account Windows. Chi controlla già la tua sessione Windows potrebbe aprirla. PERSEUS protegge da chi accede ai file da un altro account, da un altro PC o dal disco tolto dal computer, ma non da un malware già attivo sul tuo account.
- **SSD.** Sugli SSD la sovrascrittura non garantisce che il vecchio contenuto sparisca fisicamente. Per una protezione completa del disco usa anche BitLocker.
- **Cosa non viene cifrato.** I nomi delle sottocartelle restano visibili; i nomi dei file no.

---

## Compilare dal sorgente

Servono Rust (stable) e .NET SDK 10.
```powershell
.\scripts\build.ps1 -Run              # test Rust + build + avvio
.\scripts\package.ps1 -Version 0.1.0  # crea dist\Perseus-0.1.0-win-x64.zip
```

Struttura del repository:
```
core/       Rust: vault (cifratura, keystore, journal), camera, API C (perseus_core.dll)
app/        WPF .NET 10: console, finestra del menu contestuale, binding generati da csbindgen
installer/  install.cmd / install.ps1 / uninstall.ps1
scripts/    build e packaging
```
