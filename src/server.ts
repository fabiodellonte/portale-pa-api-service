import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import axios, { type AxiosInstance } from 'axios';
import { z } from 'zod';

export type RestClient = Pick<AxiosInstance, 'get' | 'post' | 'delete'>;

export function createRestClient(supabaseUrl: string): RestClient {
  return axios.create({
    baseURL: `${supabaseUrl}/rest/v1`,
    timeout: 10000,
    headers: {
      'Content-Type': 'application/json'
    }
  });
}

export async function buildServer(rest: RestClient): Promise<FastifyInstance> {
  const app = Fastify({ logger: true });
  await app.register(cors, { origin: true });

  app.get('/health', async () => ({ ok: true, service: 'portale-pa-api-service' }));

  app.get('/v1/tenants', async (_req, reply) => {
    try {
      const { data } = await rest.get('/tenants', {
        params: { select: '*', order: 'created_at.desc' }
      });
      return { items: data };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/tenants', async (req, reply) => {
    const schema = z.object({ name: z.string().min(2), codice_fiscale_ente: z.string().optional() });
    const body = schema.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: body.error.flatten() });

    try {
      const { data } = await rest.post('/tenants', body.data, {
        headers: { Prefer: 'return=representation' }
      });
      return reply.code(201).send(data?.[0] ?? body.data);
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.delete('/v1/tenants/:id', async (req, reply) => {
    const params = z.object({ id: z.string().uuid() }).safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: params.error.flatten() });

    try {
      await rest.delete('/tenants', {
        params: { id: `eq.${params.data.id}` },
        headers: { Prefer: 'return=minimal' }
      });
      return reply.code(204).send();
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/pratiche', async (req, reply) => {
    const q = z.object({ tenant_id: z.string().uuid().optional() }).safeParse(req.query);
    if (!q.success) return reply.code(400).send({ error: q.error.flatten() });

    try {
      const params: Record<string, string> = { select: '*', order: 'created_at.desc' };
      if (q.data.tenant_id) params.tenant_id = `eq.${q.data.tenant_id}`;
      const { data } = await rest.get('/pratiche', { params });
      return { items: data };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
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

    try {
      const { data } = await rest.post('/pratiche', body.data, {
        headers: { Prefer: 'return=representation' }
      });
      return reply.code(201).send(data?.[0] ?? body.data);
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/audit', async (req, reply) => {
    const q = z.object({ tenant_id: z.string().uuid().optional() }).safeParse(req.query);
    if (!q.success) return reply.code(400).send({ error: q.error.flatten() });

    try {
      const params: Record<string, string> = { select: '*', order: 'created_at.desc', limit: '200' };
      if (q.data.tenant_id) params.tenant_id = `eq.${q.data.tenant_id}`;
      const { data } = await rest.get('/audit_log', { params });
      return { items: data };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  return app;
}
