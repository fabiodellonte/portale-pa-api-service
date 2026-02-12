import Fastify from 'fastify';
import cors from '@fastify/cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';

dotenv.config();

const port = Number(process.env.PORT ?? 8080);
const host = process.env.API_HOST ?? '0.0.0.0';
const supabaseUrl = process.env.SUPABASE_URL ?? '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

const app = Fastify({ logger: true });
await app.register(cors, { origin: process.env.FRONTEND_ORIGIN ?? true });

const supabase = createClient(supabaseUrl, supabaseKey, { auth: { persistSession: false } });

app.get('/health', async () => ({ ok: true, service: 'portale-pa-api-service' }));

app.get('/v1/tenants', async (_req, reply) => {
  const { data, error } = await supabase.from('tenants').select('*').order('created_at', { ascending: false });
  if (error) return reply.code(500).send({ error: error.message });
  return { items: data };
});

app.post('/v1/tenants', async (req, reply) => {
  const schema = z.object({ name: z.string().min(2), codice_fiscale_ente: z.string().optional() });
  const body = schema.safeParse(req.body);
  if (!body.success) return reply.code(400).send({ error: body.error.flatten() });

  const { data, error } = await supabase.from('tenants').insert(body.data).select('*').single();
  if (error) return reply.code(500).send({ error: error.message });
  return reply.code(201).send(data);
});

app.get('/v1/pratiche', async (req, reply) => {
  const q = z.object({ tenant_id: z.string().uuid().optional() }).safeParse(req.query);
  if (!q.success) return reply.code(400).send({ error: q.error.flatten() });

  let query = supabase.from('pratiche').select('*').order('created_at', { ascending: false });
  if (q.data.tenant_id) query = query.eq('tenant_id', q.data.tenant_id);

  const { data, error } = await query;
  if (error) return reply.code(500).send({ error: error.message });
  return { items: data };
});

app.post('/v1/pratiche', async (req, reply) => {
  const schema = z.object({
    tenant_id: z.string().uuid(),
    codice: z.string().min(2),
    titolo: z.string().min(3),
    descrizione: z.string().optional(),
    stato: z.string().optional()
  });
  const body = schema.safeParse(req.body);
  if (!body.success) return reply.code(400).send({ error: body.error.flatten() });

  const { data, error } = await supabase.from('pratiche').insert(body.data).select('*').single();
  if (error) return reply.code(500).send({ error: error.message });
  return reply.code(201).send(data);
});

app.get('/v1/audit', async (req, reply) => {
  const q = z.object({ tenant_id: z.string().uuid().optional() }).safeParse(req.query);
  if (!q.success) return reply.code(400).send({ error: q.error.flatten() });

  let query = supabase.from('audit_log').select('*').order('created_at', { ascending: false }).limit(200);
  if (q.data.tenant_id) query = query.eq('tenant_id', q.data.tenant_id);

  const { data, error } = await query;
  if (error) return reply.code(500).send({ error: error.message });
  return { items: data };
});

app.listen({ port, host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
