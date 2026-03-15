# ChatControl Frontend

Interfaccia Vue 3 per:

- registrazione account Telegram
- login utente
- navigazione chat e messaggi
- aggiornamenti realtime via WebSocket

## Requisiti

- Node.js 18+
- npm

## Comandi

```bash
npm install
npm run dev
```

Build produzione:

```bash
npm run build
```

Lint:

```bash
npm run lint
```

## Struttura utile

- `src/views/` pagine principali (`Login`, `Signup`, `Home`, `Guide`)
- `src/services/api.js` client HTTP verso backend
- `src/router/index.js` rotte e guard autenticazione
