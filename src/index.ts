import dotenv from 'dotenv';
import { buildServer, createRestClient } from './server.js';

dotenv.config();

const port = Number(process.env.PORT ?? 8080);
const host = process.env.API_HOST ?? '0.0.0.0';
const supabaseUrl = process.env.SUPABASE_URL ?? 'http://localhost:54321';

const rest = createRestClient(supabaseUrl);
const app = await buildServer(rest);

app.listen({ port, host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
