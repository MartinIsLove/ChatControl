# ChatControl

Pannello web per collegare un account Telegram, autenticarsi e gestire chat/messaggi in tempo reale in modo criptato End-To-End sull'infrastruttura Telegram già esistente.

## Prerequisiti
- git
- Python 3.10+
- Node.js 18+
- OpenSSL (per i certificati HTTPS locali)
- Age

## Setup backend

1. Crea e attiva un virtual environment nella root del progetto.
2. Installa le dipendenze:

```bash
pip install -r requirements.txt
```

3. Crea un file `.env` nella root con almeno:

```env
SECRET_PEPPER=<valore_lungo_casuale_esadecimale>
```

## Certificati locali

Genera certificati self-signed e copia `cert.pem` + `key.pem` in entrambe le cartelle:

- `Backend/certs/`
- `Frontend/certs/`

Comando esempio:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes
```

## Avvio backend

Dalla cartella `Backend/`:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile ./certs/key.pem --ssl-certfile ./certs/cert.pem
```

Se si sta utilizzando su un dispositivo Linux è possibile aggiungere in coda al comando 

```bash
--loop auto
```

Per poter abilitare uvicorn loop
## Avvio frontend

Dalla cartella `Frontend/`:

```bash
npm install
npm install lottie-web pako
npm run dev
```

## Note operative

- Il frontend usa API HTTPS locali del backend.
- Se apri da browser esterno, accetta il certificato self-signed la prima volta.
- Se si vuole abilitare il caching dei media, si deve andare dal browser:
    chrome://flags/#unsafely-treat-insecure-origin-as-secure
  ed inserire l'indirizzo del server, in modo che il browser sappia che quella fonte è sicura.