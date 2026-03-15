# ChatControl

Pannello web per collegare un account Telegram, autenticarsi e gestire chat/messaggi in tempo reale.

## Requisiti

- Python 3.10+
- Node.js 18+
- OpenSSL (per i certificati HTTPS locali)

## Setup backend

1. Crea e attiva un virtual environment nella root del progetto.
2. Installa le dipendenze:

```bash
pip install -r requirements.txt
```

3. Crea un file `.env` nella root con almeno:

```env
SECRET_PEPPER=<valore_lungo_casuale_esadecimale>
SECRET_KEY=<chiave_base64>
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

## Avvio frontend

Dalla cartella `Frontend/`:

```bash
npm install
npm run dev
```

## Note operative

- Il frontend usa API HTTPS locali del backend.
- Se apri da browser esterno, accetta il certificato self-signed la prima volta.
