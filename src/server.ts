import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import axios, { type AxiosInstance } from 'axios';
import { z } from 'zod';

export type RestClient = Pick<AxiosInstance, 'get' | 'post' | 'delete'>;

const tenantSchema = z.object({ name: z.string().min(2), codice_fiscale_ente: z.string().optional() });
const idParamSchema = z.object({ id: z.string().uuid() });
const tenantQuerySchema = z.object({ tenant_id: z.string().uuid().optional() });

const segnalazioniQuerySchema = z.object({
  tenant_id: z.string().uuid(),
  category_id: z.string().uuid().optional(),
  neighborhood_id: z.string().uuid().optional(),
  status: z.string().optional(),
  search: z.string().min(2).optional(),
  sort: z.enum(['created_at.desc', 'created_at.asc', 'updated_at.desc', 'updated_at.asc', 'votes.desc']).optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(20)
});

const toggleSchema = z.object({ tenant_id: z.string().uuid(), user_id: z.string().uuid() });

const wizardPayloadSchema = z.object({
  tenant_id: z.string().uuid(),
  titolo: z.string().min(3),
  descrizione: z.string().min(10),
  category_id: z.string().uuid().optional(),
  neighborhood_id: z.string().uuid().optional(),
  address: z.string().optional(),
  lat: z.number().optional(),
  lng: z.number().optional(),
  tags: z.array(z.string().min(1)).max(10).optional(),
  attachments: z.array(z.string().url()).max(8).optional(),
  metadata: z.record(z.any()).optional(),
  user_id: z.string().uuid().optional()
});

type ToggleKind = 'vote' | 'follow';

export function createRestClient(supabaseUrl: string): RestClient {
  return axios.create({
    baseURL: `${supabaseUrl}/rest/v1`,
    timeout: 10000,
    headers: {
      'Content-Type': 'application/json'
    }
  });
}

function isInvalid<T>(reply: any, parsed: z.SafeParseReturnType<any, T>): parsed is z.SafeParseError<any> {
  if (!parsed.success) {
    reply.code(400).send({ error: parsed.error.flatten() });
    return true;
  }
  return false;
}

function codiceSegnalazione() {
  return `SGN-${Date.now()}`;
}

async function ensureSegnalazioneTenant(rest: RestClient, segnalazioneId: string, tenantId: string) {
  const { data } = await rest.get('/segnalazioni', {
    params: { select: 'id,tenant_id', id: `eq.${segnalazioneId}`, tenant_id: `eq.${tenantId}`, limit: '1' }
  });
  return data?.[0];
}

async function toggleEntity(
  rest: RestClient,
  kind: ToggleKind,
  tenantId: string,
  segnalazioneId: string,
  userId: string
) {
  const table = kind === 'vote' ? '/segnalazione_votes' : '/segnalazione_follows';

  const { data: existing } = await rest.get(table, {
    params: {
      select: 'id',
      tenant_id: `eq.${tenantId}`,
      segnalazione_id: `eq.${segnalazioneId}`,
      user_id: `eq.${userId}`,
      limit: '1'
    }
  });

  const row = existing?.[0];
  const active = !row;

  if (row) {
    await rest.delete(table, {
      params: { id: `eq.${row.id}` },
      headers: { Prefer: 'return=minimal' }
    });
  } else {
    await rest.post(table, { tenant_id: tenantId, segnalazione_id: segnalazioneId, user_id: userId }, {
      headers: { Prefer: 'return=representation' }
    });
  }

  const { data: all } = await rest.get(table, {
    params: { select: 'id', tenant_id: `eq.${tenantId}`, segnalazione_id: `eq.${segnalazioneId}` }
  });

  return { active, count: all?.length ?? 0 };
}

export async function buildServer(rest: RestClient): Promise<FastifyInstance> {
  const app = Fastify({ logger: true });
  await app.register(cors, { origin: true });

  app.get('/health', async () => ({ ok: true, service: 'portale-pa-api-service' }));

  app.get('/v1/tenants', async (_req, reply) => {
    try {
      const { data } = await rest.get('/tenants', { params: { select: '*', order: 'created_at.desc' } });
      return { items: data };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/tenants', async (req, reply) => {
    const body = tenantSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    try {
      const { data } = await rest.post('/tenants', body.data, { headers: { Prefer: 'return=representation' } });
      return reply.code(201).send(data?.[0] ?? body.data);
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.delete('/v1/tenants/:id', async (req, reply) => {
    const params = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, params)) return;

    try {
      await rest.delete('/tenants', { params: { id: `eq.${params.data.id}` }, headers: { Prefer: 'return=minimal' } });
      return reply.code(204).send();
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/pratiche', async (req, reply) => {
    const q = tenantQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

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
    if (isInvalid(reply, body)) return;

    try {
      const { data } = await rest.post('/pratiche', body.data, { headers: { Prefer: 'return=representation' } });
      return reply.code(201).send(data?.[0] ?? body.data);
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/audit', async (req, reply) => {
    const q = tenantQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

    try {
      const params: Record<string, string> = { select: '*', order: 'created_at.desc', limit: '200' };
      if (q.data.tenant_id) params.tenant_id = `eq.${q.data.tenant_id}`;
      const { data } = await rest.get('/audit_log', { params });
      return { items: data };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/public/metrics', async (req, reply) => {
    const q = tenantQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

    try {
      const segnalazioniParams: Record<string, string> = { select: 'id,stato' };
      if (q.data.tenant_id) segnalazioniParams.tenant_id = `eq.${q.data.tenant_id}`;

      const [segnalazioni, votes, follows] = await Promise.all([
        rest.get('/segnalazioni', { params: segnalazioniParams }),
        rest.get('/segnalazione_votes', { params: q.data.tenant_id ? { select: 'id', tenant_id: `eq.${q.data.tenant_id}` } : { select: 'id' } }),
        rest.get('/segnalazione_follows', { params: q.data.tenant_id ? { select: 'id', tenant_id: `eq.${q.data.tenant_id}` } : { select: 'id' } })
      ]);

      const byStatus = (segnalazioni.data ?? []).reduce((acc: Record<string, number>, item: { stato: string }) => {
        acc[item.stato] = (acc[item.stato] ?? 0) + 1;
        return acc;
      }, {});

      return {
        tenant_id: q.data.tenant_id ?? null,
        total_segnalazioni: segnalazioni.data?.length ?? 0,
        total_votes: votes.data?.length ?? 0,
        total_follows: follows.data?.length ?? 0,
        by_status: byStatus
      };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/segnalazioni', async (req, reply) => {
    const q = segnalazioniQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

    try {
      const offset = (q.data.page - 1) * q.data.page_size;
      const params: Record<string, string> = {
        select: '*',
        tenant_id: `eq.${q.data.tenant_id}`,
        order: q.data.sort && q.data.sort !== 'votes.desc' ? q.data.sort : 'created_at.desc',
        limit: String(q.data.page_size),
        offset: String(offset)
      };
      if (q.data.category_id) params.category_id = `eq.${q.data.category_id}`;
      if (q.data.neighborhood_id) params.neighborhood_id = `eq.${q.data.neighborhood_id}`;
      if (q.data.status) params.stato = `eq.${q.data.status}`;
      if (q.data.search) {
        params.or = `(titolo.ilike.*${q.data.search}*,descrizione.ilike.*${q.data.search}*)`;
      }

      const { data } = await rest.get('/segnalazioni', { params });
      return { items: data ?? [], page: q.data.page, page_size: q.data.page_size };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/segnalazioni/:id', async (req, reply) => {
    const p = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, p)) return;

    try {
      const { data } = await rest.get('/segnalazioni', {
        params: {
          select: '*',
          id: `eq.${p.data.id}`,
          limit: '1'
        }
      });

      if (!data?.[0]) return reply.code(404).send({ error: 'Segnalazione not found' });

      const segnalazione = data[0];
      const [timeline, votes, follows, snapshots] = await Promise.all([
        rest.get('/segnalazione_timeline_events', { params: { select: '*', segnalazione_id: `eq.${p.data.id}`, order: 'created_at.desc', limit: '50' } }),
        rest.get('/segnalazione_votes', { params: { select: 'id,user_id', segnalazione_id: `eq.${p.data.id}` } }),
        rest.get('/segnalazione_follows', { params: { select: 'id,user_id', segnalazione_id: `eq.${p.data.id}` } }),
        rest.get('/segnalazione_report_snapshots', { params: { select: '*', segnalazione_id: `eq.${p.data.id}`, order: 'created_at.desc', limit: '10' } })
      ]);

      return {
        ...segnalazione,
        votes_count: votes.data?.length ?? 0,
        follows_count: follows.data?.length ?? 0,
        timeline: timeline.data ?? [],
        snapshots: snapshots.data ?? []
      };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/segnalazioni/:id/vote-toggle', async (req, reply) => {
    const p = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, p)) return;
    const body = toggleSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    try {
      const found = await ensureSegnalazioneTenant(rest, p.data.id, body.data.tenant_id);
      if (!found) return reply.code(404).send({ error: 'Segnalazione not found for tenant' });

      const result = await toggleEntity(rest, 'vote', body.data.tenant_id, p.data.id, body.data.user_id);
      return { segnalazione_id: p.data.id, vote_active: result.active, votes_count: result.count };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/segnalazioni/:id/follow-toggle', async (req, reply) => {
    const p = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, p)) return;
    const body = toggleSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    try {
      const found = await ensureSegnalazioneTenant(rest, p.data.id, body.data.tenant_id);
      if (!found) return reply.code(404).send({ error: 'Segnalazione not found for tenant' });

      const result = await toggleEntity(rest, 'follow', body.data.tenant_id, p.data.id, body.data.user_id);
      return { segnalazione_id: p.data.id, follow_active: result.active, follows_count: result.count };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/segnalazioni/wizard', async (req, reply) => {
    const body = wizardPayloadSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    try {
      const createdPayload = {
        tenant_id: body.data.tenant_id,
        codice: codiceSegnalazione(),
        titolo: body.data.titolo,
        descrizione: body.data.descrizione,
        category_id: body.data.category_id,
        neighborhood_id: body.data.neighborhood_id,
        address: body.data.address,
        lat: body.data.lat,
        lng: body.data.lng,
        attachments: body.data.attachments ?? [],
        tags: body.data.tags ?? [],
        metadata: body.data.metadata ?? {},
        created_by: body.data.user_id
      };

      const { data } = await rest.post('/segnalazioni', createdPayload, { headers: { Prefer: 'return=representation' } });
      const segnalazione = data?.[0];

      if (!segnalazione?.id) {
        return reply.code(500).send({ error: 'Unable to create segnalazione' });
      }

      await Promise.all([
        rest.post('/segnalazione_timeline_events', {
          tenant_id: body.data.tenant_id,
          segnalazione_id: segnalazione.id,
          event_type: 'created',
          visibility: 'public',
          message: 'Segnalazione inserita dal wizard',
          payload: { source: 'wizard' },
          created_by: body.data.user_id
        }),
        rest.post('/segnalazione_report_snapshots', {
          tenant_id: body.data.tenant_id,
          segnalazione_id: segnalazione.id,
          status: segnalazione.stato ?? 'in_attesa',
          severity: segnalazione.severita ?? 'media',
          priority: segnalazione.priorita ?? 'media',
          snapshot_data: { titolo: segnalazione.titolo, descrizione: segnalazione.descrizione },
          changed_by: body.data.user_id
        }),
        rest.post('/audit_log', {
          tenant_id: body.data.tenant_id,
          actor_id: body.data.user_id,
          action: 'segnalazione_created',
          entity_type: 'segnalazioni',
          entity_id: segnalazione.id,
          metadata: { source: 'wizard', category_id: body.data.category_id }
        })
      ]);

      return reply.code(201).send({ id: segnalazione.id, codice: segnalazione.codice, stato: segnalazione.stato, titolo: segnalazione.titolo });
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  return app;
}

