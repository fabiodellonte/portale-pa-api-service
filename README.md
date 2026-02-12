# portale-pa-api-service

Layer intermedio API-first tra frontend e Supabase.

## Obiettivi
- Logica business e validazioni server-side
- Orchestrazione accesso Supabase
- Endpoint stabili per frontend
- Pronto per integrazione Ollama futura

## Avvio locale
```powershell
cp .env.example .env
npm install
npm run dev
```

## Docker
```powershell
docker build -t portale-pa-api-service:local .
docker run --rm -p 8080:8080 --env-file .env portale-pa-api-service:local
```
