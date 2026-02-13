import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import axios, { type AxiosInstance, type Method } from 'axios';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { z } from 'zod';

export type RestClient = Pick<AxiosInstance, 'get' | 'post' | 'delete' | 'patch'>;
export type AuthClient = Pick<AxiosInstance, 'request'>;

type LegacyRoleCode = 'super_admin' | 'tenant_admin' | 'operatore' | 'cittadino';
type PortalRole = 'admin' | 'maintainer' | 'citizen';
type RoleCode = LegacyRoleCode | PortalRole;

const tenantSchema = z.object({ name: z.string().min(2), codice_fiscale_ente: z.string().optional() });
const idParamSchema = z.object({ id: z.string().uuid() });
const tenantQuerySchema = z.object({ tenant_id: z.string().uuid().optional() });
const accessQuerySchema = z.object({ user_id: z.string().uuid().optional(), tenant_id: z.string().uuid().optional() });

const languageSchema = z.object({ language: z.enum(['it', 'en']) });
const brandingSchema = z.object({
  logo_url: z.string().url().optional().nullable(),
  primary_color: z.string().regex(/^#([A-Fa-f0-9]{6})$/),
  secondary_color: z.string().regex(/^#([A-Fa-f0-9]{6})$/),
  font_family: z.string().max(120).optional().nullable(),
  header_variant: z.enum(['standard', 'compact']).optional().nullable(),
  footer_text: z.string().max(240).optional().nullable()
});
const roleAssignmentSchema = z.object({
  tenant_id: z.string().uuid(),
  role_code: z.enum(['super_admin', 'tenant_admin', 'operatore', 'cittadino', 'admin', 'maintainer', 'citizen'])
});

const bugReportSchema = z.object({
  title: z.string().min(3).max(180),
  description: z.string().min(10).max(4000),
  page_url: z.string().url().optional()
});

const docSchema = z.object({
  slug: z.string().min(2).max(80).regex(/^[a-z0-9-]+$/),
  title: z.string().min(3).max(180),
  content_md: z.string().min(10),
  is_published: z.boolean().default(true),
  sort_order: z.number().int().min(0).max(999).default(0)
});

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

const segnalazioniDuplicatesQuerySchema = z.object({
  tenant_id: z.string().uuid(),
  titolo: z.string().min(3),
  limit: z.coerce.number().int().min(1).max(20).default(5)
});

const prioritiesQuerySchema = z.object({
  tenant_id: z.string().uuid(),
  limit: z.coerce.number().int().min(1).max(20).default(10)
});

const notificationsQuerySchema = z.object({
  tenant_id: z.string().uuid(),
  user_id: z.string().uuid().optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(50).default(25)
});

const assistedTagsQuerySchema = z.object({
  tenant_id: z.string().uuid(),
  q: z.string().min(1).max(60).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20)
});

const assistedAddressQuerySchema = z.object({
  tenant_id: z.string().uuid(),
  q: z.string().min(2).max(120),
  limit: z.coerce.number().int().min(1).max(20).default(8)
});

const assistedAddressValidateSchema = z.object({
  tenant_id: z.string().uuid(),
  catalog_id: z.string().uuid(),
  address: z.string().min(3)
});

const toggleSchema = z.object({ tenant_id: z.string().uuid(), user_id: z.string().uuid() });

const addressValidationSchema = z.object({
  validated: z.boolean(),
  source: z.literal('tenant_address_catalog'),
  catalog_id: z.string().uuid(),
  normalized_address: z.string().min(3),
  reference_code: z.string().min(2),
  lat: z.number(),
  lng: z.number(),
  confidence: z.number().min(0).max(1).optional()
});

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
  tag_slugs: z.array(z.string().min(1)).max(10).optional(),
  address_validation: addressValidationSchema.optional(),
  attachments: z.array(z.string().url()).max(8).optional(),
  metadata: z.record(z.any()).optional(),
  user_id: z.string().uuid().optional()
});

const adminSegnalazioneSchema = z.object({
  tenant_id: z.string().uuid()
});

const statusTransitionSchema = adminSegnalazioneSchema.extend({
  status: z.enum(['in_attesa', 'presa_in_carico', 'in_lavorazione', 'risolta', 'chiusa', 'respinta']),
  message: z.string().min(3).max(500).optional()
});

const assignSchema = adminSegnalazioneSchema.extend({
  assigned_to: z.string().uuid(),
  message: z.string().min(3).max(500).optional()
});

const publicResponseSchema = adminSegnalazioneSchema.extend({
  message: z.string().min(3).max(2000)
});

const moderationFlagsSchema = adminSegnalazioneSchema.extend({
  flags: z.object({
    hidden: z.boolean().optional(),
    abusive: z.boolean().optional(),
    duplicate_of: z.string().uuid().optional(),
    requires_review: z.boolean().optional(),
    note: z.string().max(500).optional()
  })
});

const rankingFactors = [
  { factor: 'votes', description: 'Supporto civico diretto', weight: 0.4 },
  { factor: 'severity', description: 'Impatto e gravità', weight: 0.25 },
  { factor: 'freshness', description: 'Recenza segnalazione', weight: 0.2 },
  { factor: 'follows', description: 'Interesse continuativo', weight: 0.15 }
] as const;

const allowedTransitions: Record<string, string[]> = {
  in_attesa: ['presa_in_carico', 'respinta'],
  presa_in_carico: ['in_lavorazione', 'chiusa'],
  in_lavorazione: ['risolta', 'chiusa'],
  risolta: ['chiusa'],
  chiusa: [],
  respinta: []
};

type ToggleKind = 'vote' | 'follow';

type AccessCtx = {
  userId: string;
  tenantId: string;
  roleCodes: RoleCode[];
  portalRoles: PortalRole[];
  portalRole: PortalRole;
  isGlobalAdmin: boolean;
  isTenantAdmin: boolean;
};

type EmailNotificationRecipient = {
  userId: string;
  email: string;
};

type EmailChannelConfig = {
  provider: string;
  from: string;
};

type DemoModeAction = 'status' | 'on' | 'off';
type DemoModeState = 'on' | 'off' | 'unknown';
type DemoModeExecutor = (action: DemoModeAction) => Promise<{ state: DemoModeState; output: string }>;
type BuildServerOptions = {
  demoModeExecutor?: DemoModeExecutor;
};

const execFileAsync = promisify(execFile);

export function createRestClient(supabaseUrl: string): RestClient {
  return axios.create({
    baseURL: `${supabaseUrl}/rest/v1`,
    timeout: 10000,
    headers: {
      'Content-Type': 'application/json'
    }
  });
}

export function createAuthClient(supabaseUrl: string): AuthClient {
  return axios.create({
    baseURL: `${supabaseUrl}/auth/v1`,
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

function normalizeText(value: string) {
  return value
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function isAddressValidationStrict() {
  return (process.env.WIZARD_ADDRESS_VALIDATION_MODE ?? 'strict').toLowerCase() !== 'soft';
}

function sanitizeHeaders(headers: Record<string, unknown>) {
  const denied = new Set(['host', 'connection', 'content-length']);
  return Object.entries(headers).reduce<Record<string, string>>((acc, [key, value]) => {
    if (denied.has(key.toLowerCase())) return acc;
    if (typeof value === 'string') acc[key] = value;
    return acc;
  }, {});
}

function loadEmailChannelConfig(): EmailChannelConfig {
  return {
    provider: process.env.NOTIFICATION_EMAIL_PROVIDER ?? 'smtp',
    from: process.env.NOTIFICATION_FROM_EMAIL ?? 'noreply@portale-pa.local'
  };
}

function parseDemoModeState(output: string): DemoModeState {
  const normalized = output.toLowerCase();
  if (normalized.includes('demo mode on') || normalized.includes('modalita demo on')) return 'on';
  if (normalized.includes('demo mode off') || normalized.includes('modalita demo off')) return 'off';
  if (normalized.includes('no real backup recorded yet')) return 'off';
  return 'unknown';
}

function createDemoModeExecutor(scriptPath: string): DemoModeExecutor {
  return async (action) => {
    const { stdout, stderr } = await execFileAsync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, '-Mode', action], {
      windowsHide: true
    });
    const output = [stdout, stderr].filter(Boolean).join('\n').trim();
    return { state: parseDemoModeState(output), output };
  };
}

function isDemoModeSwitchEnabled() {
  return process.env.ENABLE_DEMO_MODE_SWITCH === 'true';
}

async function queueAdminEmailNotification(
  rest: RestClient,
  recipient: EmailNotificationRecipient,
  payload: { bugReportId: string; tenantId: string; reporterId: string; title: string; description: string; pageUrl?: string }
) {
  const emailConfig = loadEmailChannelConfig();
  return rest.post('/admin_email_notifications', {
    bug_report_id: payload.bugReportId,
    recipient_user_id: recipient.userId,
    recipient_email: recipient.email,
    provider: emailConfig.provider,
    sender_email: emailConfig.from,
    subject: `[Portale PA] Nuovo bug report: ${payload.title}`,
    body: `Tenant ${payload.tenantId}\nSegnalato da ${payload.reporterId}\nTitolo: ${payload.title}\nPagina: ${payload.pageUrl ?? 'n/d'}\n\n${payload.description}`,
    delivery_status: 'queued'
  });
}

async function createAdminTrail(rest: RestClient, input: {
  tenantId: string;
  segnalazioneId: string;
  actorId: string;
  eventType: string;
  message: string;
  payload?: Record<string, unknown>;
  action: string;
  metadata?: Record<string, unknown>;
}) {
  await Promise.all([
    rest.post('/segnalazione_timeline_events', {
      tenant_id: input.tenantId,
      segnalazione_id: input.segnalazioneId,
      event_type: input.eventType,
      visibility: 'public',
      message: input.message,
      payload: input.payload ?? {},
      created_by: input.actorId
    }),
    rest.post('/audit_log', {
      tenant_id: input.tenantId,
      actor_id: input.actorId,
      action: input.action,
      entity_type: 'segnalazioni',
      entity_id: input.segnalazioneId,
      metadata: input.metadata ?? {}
    })
  ]);
}

async function ensureSegnalazioneTenant(rest: RestClient, segnalazioneId: string, tenantId: string) {
  const { data } = await rest.get('/segnalazioni', {
    params: { select: 'id,tenant_id,stato,metadata,moderation_flags,public_response', id: `eq.${segnalazioneId}`, tenant_id: `eq.${tenantId}`, limit: '1' }
  });
  return data?.[0];
}

async function toggleEntity(rest: RestClient, kind: ToggleKind, tenantId: string, segnalazioneId: string, userId: string) {
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
    await rest.post(
      table,
      { tenant_id: tenantId, segnalazione_id: segnalazioneId, user_id: userId },
      {
        headers: { Prefer: 'return=representation' }
      }
    );
  }

  const { data: all } = await rest.get(table, {
    params: { select: 'id', tenant_id: `eq.${tenantId}`, segnalazione_id: `eq.${segnalazioneId}` }
  });

  return { active, count: all?.length ?? 0 };
}

const roleCodeToPortalRole: Record<RoleCode, PortalRole> = {
  super_admin: 'admin',
  tenant_admin: 'maintainer',
  operatore: 'maintainer',
  cittadino: 'citizen',
  admin: 'admin',
  maintainer: 'maintainer',
  citizen: 'citizen'
};

function resolvePortalRoles(roleCodes: RoleCode[]): PortalRole[] {
  const normalized = Array.from(new Set(roleCodes.map((code) => roleCodeToPortalRole[code]).filter(Boolean)));
  if (normalized.length === 0) return ['citizen'];
  return normalized.includes('admin')
    ? ['admin', 'maintainer', 'citizen']
    : normalized.includes('maintainer')
      ? ['maintainer', 'citizen']
      : ['citizen'];
}

async function loadAccess(rest: RestClient, userId: string, tenantId: string): Promise<AccessCtx> {
  const { data: profileRows } = await rest.get('/user_profiles', {
    params: { select: 'id,tenant_id', id: `eq.${userId}`, limit: '1' }
  });
  const profile = profileRows?.[0];
  if (!profile) {
    throw new Error('USER_NOT_FOUND');
  }

  const { data: userRoles } = await rest.get('/user_roles', {
    params: {
      select: 'role_id,roles(code)',
      user_id: `eq.${userId}`
    }
  });

  const roleCodes = (userRoles ?? [])
    .map((r: any) => r.roles?.code)
    .filter((code: unknown): code is RoleCode => typeof code === 'string' && code in roleCodeToPortalRole);

  const portalRoles = resolvePortalRoles(roleCodes);

  return {
    userId,
    tenantId,
    roleCodes,
    portalRoles,
    portalRole: portalRoles[0],
    isGlobalAdmin: portalRoles.includes('admin'),
    isTenantAdmin: profile.tenant_id === tenantId && (portalRoles.includes('admin') || portalRoles.includes('maintainer'))
  };
}

function extractAuth(req: FastifyRequest) {
  const userId = req.headers['x-user-id'];
  const tenantId = req.headers['x-tenant-id'];

  if (typeof userId !== 'string' || typeof tenantId !== 'string') {
    return null;
  }

  const parsed = z.object({ userId: z.string().uuid(), tenantId: z.string().uuid() }).safeParse({ userId, tenantId });
  return parsed.success ? parsed.data : null;
}

async function requireAccess(
  req: FastifyRequest,
  reply: FastifyReply,
  rest: RestClient,
  mode: 'authenticated' | 'tenant_admin' | 'global_admin'
): Promise<AccessCtx | null> {
  const auth = extractAuth(req);
  if (!auth) {
    reply.code(401).send({ error: 'Missing or invalid x-user-id/x-tenant-id headers' });
    return null;
  }

  try {
    const access = await loadAccess(rest, auth.userId, auth.tenantId);
    if (mode === 'authenticated') return access;
    if (mode === 'tenant_admin' && !(access.isGlobalAdmin || access.isTenantAdmin)) {
      reply.code(403).send({ error: 'Insufficient role for tenant admin operation' });
      return null;
    }
    if (mode === 'global_admin' && !access.isGlobalAdmin) {
      reply.code(403).send({ error: 'Insufficient role for global admin operation' });
      return null;
    }
    return access;
  } catch (error: any) {
    if (error.message === 'USER_NOT_FOUND') {
      reply.code(401).send({ error: 'Unknown user profile' });
      return null;
    }
    reply.code(500).send({ error: error.message });
    return null;
  }
}

export async function buildServer(
  rest: RestClient,
  auth: AuthClient = createAuthClient(process.env.SUPABASE_URL ?? 'http://localhost:54321'),
  options: BuildServerOptions = {}
): Promise<FastifyInstance> {
  const app = Fastify({ logger: true });
  await app.register(cors, { origin: true });

  const demoModeExecutor = options.demoModeExecutor ?? createDemoModeExecutor(
    process.env.DEMO_MODE_SCRIPT_PATH ?? path.resolve(process.cwd(), '..', 'portale-pa-backend-supabase', 'scripts', 'demo-mode.ps1')
  );

  app.get('/health', async () => ({ ok: true, service: 'portale-pa-api-service' }));

  app.route({
    method: ['GET', 'POST'],
    url: '/v1/auth/*',
    handler: async (req, reply) => {
      try {
        const path = ((req.params as { '*': string })['*'] ?? '').trim();
        const response = await auth.request({
          method: req.method.toUpperCase() as Method,
          url: `/${path}`,
          params: req.query as Record<string, unknown>,
          data: req.body,
          headers: sanitizeHeaders(req.headers as Record<string, unknown>)
        });
        return reply.code(response.status).send(response.data);
      } catch (error: any) {
        const status = error?.response?.status ?? 500;
        return reply.code(status).send(error?.response?.data ?? { error: error.message });
      }
    }
  });

  app.get('/v1/me/access', async (req, reply) => {
    const auth = await requireAccess(req, reply, rest, 'authenticated');
    if (!auth) return;

    return {
      user_id: auth.userId,
      tenant_id: auth.tenantId,
      roles: auth.roleCodes,
      portal_roles: auth.portalRoles,
      portal_role: auth.portalRole,
      can_manage_branding: auth.isGlobalAdmin || auth.isTenantAdmin,
      can_manage_roles: auth.isGlobalAdmin,
      can_manage_language: true
    };
  });

  app.get('/v1/admin/demo-mode', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'global_admin');
    if (!access) return;
    if (!isDemoModeSwitchEnabled()) {
      return reply.code(404).send({ error: 'Demo mode switch disabled' });
    }

    try {
      const result = await demoModeExecutor('status');
      return { state: result.state, output: result.output };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/admin/demo-mode', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'global_admin');
    if (!access) return;
    if (!isDemoModeSwitchEnabled()) {
      return reply.code(404).send({ error: 'Demo mode switch disabled' });
    }

    const body = z.object({ mode: z.enum(['on', 'off']) }).safeParse(req.body);
    if (isInvalid(reply, body)) return;

    try {
      const switched = await demoModeExecutor(body.data.mode);
      const current = await demoModeExecutor('status');
      return {
        requested_mode: body.data.mode,
        state: current.state,
        output: switched.output,
        status_output: current.output
      };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/me/preferences', async (req, reply) => {
    const auth = await requireAccess(req, reply, rest, 'authenticated');
    if (!auth) return;

    const { data } = await rest.get('/user_profiles', { params: { select: 'id,language', id: `eq.${auth.userId}`, limit: '1' } });
    return { user_id: auth.userId, language: data?.[0]?.language ?? 'it' };
  });

  app.put('/v1/me/preferences/language', async (req, reply) => {
    const auth = await requireAccess(req, reply, rest, 'authenticated');
    if (!auth) return;

    const body = languageSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    const { data } = await rest.patch('/user_profiles', { language: body.data.language }, {
      params: { id: `eq.${auth.userId}` },
      headers: { Prefer: 'return=representation' }
    });

    return { user_id: auth.userId, language: data?.[0]?.language ?? body.data.language };
  });

  app.get('/v1/tenants/:id/branding', async (req, reply) => {
    const auth = await requireAccess(req, reply, rest, 'authenticated');
    if (!auth) return;

    const params = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, params)) return;

    if (!auth.isGlobalAdmin && auth.tenantId !== params.data.id) {
      return reply.code(403).send({ error: 'Cannot read another tenant branding' });
    }

    const { data } = await rest.get('/tenant_branding', {
      params: { select: '*', tenant_id: `eq.${params.data.id}`, limit: '1' }
    });

    return data?.[0] ?? { tenant_id: params.data.id, primary_color: '#0055A4', secondary_color: '#FFFFFF' };
  });

  app.put('/v1/tenants/:id/branding', async (req, reply) => {
    const auth = await requireAccess(req, reply, rest, 'tenant_admin');
    if (!auth) return;

    const params = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, params)) return;
    const body = brandingSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    if (!auth.isGlobalAdmin && auth.tenantId !== params.data.id) {
      return reply.code(403).send({ error: 'Cannot update another tenant branding' });
    }

    const payload = { tenant_id: params.data.id, ...body.data, updated_by: auth.userId };
    const { data } = await rest.post('/tenant_branding', payload, {
      params: { on_conflict: 'tenant_id' },
      headers: { Prefer: 'resolution=merge-duplicates,return=representation' }
    });

    return data?.[0] ?? payload;
  });

  app.get('/v1/admin/roles', async (req, reply) => {
    const auth = await requireAccess(req, reply, rest, 'global_admin');
    if (!auth) return;

    const query = accessQuerySchema.safeParse(req.query);
    if (isInvalid(reply, query)) return;

    const userFilter = query.data.user_id ? { user_id: `eq.${query.data.user_id}` } : {};
    const { data } = await rest.get('/user_roles', {
      params: {
        select: 'user_id,role_id,roles(code,name),user_profiles(tenant_id,full_name)',
        ...userFilter
      }
    });

    const rows = (data ?? []).filter((row: any) => !query.data.tenant_id || row.user_profiles?.tenant_id === query.data.tenant_id);
    return { items: rows };
  });

  app.put('/v1/admin/roles/:id', async (req, reply) => {
    const auth = await requireAccess(req, reply, rest, 'global_admin');
    if (!auth) return;

    const params = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, params)) return;
    const body = roleAssignmentSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    const { data: profiles } = await rest.get('/user_profiles', { params: { select: 'id,tenant_id', id: `eq.${params.data.id}`, limit: '1' } });
    if (!profiles?.[0]) return reply.code(404).send({ error: 'User profile not found' });
    if (profiles[0].tenant_id !== body.data.tenant_id) return reply.code(400).send({ error: 'tenant_id does not match profile tenant' });

    const { data: roleRows } = await rest.get('/roles', { params: { select: 'id,code', code: `eq.${body.data.role_code}`, limit: '1' } });
    const role = roleRows?.[0];
    if (!role) return reply.code(404).send({ error: 'Role not found' });

    await rest.post('/user_roles', { user_id: params.data.id, role_id: role.id }, {
      headers: { Prefer: 'resolution=ignore-duplicates,return=representation' }
    });

    return { user_id: params.data.id, tenant_id: body.data.tenant_id, role_code: role.code };
  });

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

  app.get('/v1/public/transparency/ranking', async () => {
    const totalWeight = rankingFactors.reduce((acc, item) => acc + item.weight, 0);
    return {
      algorithm: 'weighted_sum',
      version: '2026-02-phase3',
      normalized: true,
      total_weight: totalWeight,
      factors: rankingFactors
    };
  });

  app.get('/v1/segnalazioni/duplicates', async (req, reply) => {
    const q = segnalazioniDuplicatesQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

    const search = q.data.titolo.trim().split(/\s+/).slice(0, 4).join(' ');

    try {
      const { data } = await rest.get('/segnalazioni', {
        params: {
          select: 'id,codice,titolo,stato,updated_at',
          tenant_id: `eq.${q.data.tenant_id}`,
          or: `(titolo.ilike.*${search}*,descrizione.ilike.*${search}*)`,
          order: 'updated_at.desc',
          limit: String(q.data.limit)
        }
      });

      return { items: data ?? [] };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/segnalazioni/priorities', async (req, reply) => {
    const q = prioritiesQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

    try {
      const [segnalazioniRes, votesRes, categoriesRes] = await Promise.all([
        rest.get('/segnalazioni', {
          params: {
            select: 'id,titolo,stato,priorita,severita,category_id,updated_at',
            tenant_id: `eq.${q.data.tenant_id}`,
            order: 'updated_at.desc',
            limit: '200'
          }
        }),
        rest.get('/segnalazione_votes', {
          params: {
            select: 'segnalazione_id',
            tenant_id: `eq.${q.data.tenant_id}`
          }
        }),
        rest.get('/segnalazione_categories', {
          params: {
            select: 'id,name',
            tenant_id: `eq.${q.data.tenant_id}`
          }
        })
      ]);

      const votesBySegnalazione = (votesRes.data ?? []).reduce((acc: Record<string, number>, row: { segnalazione_id?: string }) => {
        if (!row.segnalazione_id) return acc;
        acc[row.segnalazione_id] = (acc[row.segnalazione_id] ?? 0) + 1;
        return acc;
      }, {});

      const categoryById = (categoriesRes.data ?? []).reduce((acc: Record<string, string>, row: { id?: string; name?: string }) => {
        if (row.id && row.name) acc[row.id] = row.name;
        return acc;
      }, {});

      const priorityWeight: Record<string, number> = { bassa: 1, media: 2, alta: 3, urgente: 4 };
      const severityWeight: Record<string, number> = { bassa: 1, media: 2, alta: 3, critica: 4 };

      const items = (segnalazioniRes.data ?? [])
        .map((row: any) => {
          const supporti = votesBySegnalazione[row.id] ?? 0;
          const updatedAt = row.updated_at ? new Date(row.updated_at).getTime() : Date.now();
          const ageDays = Math.max(0, (Date.now() - updatedAt) / (1000 * 60 * 60 * 24));
          const trend = ageDays <= 3 ? '+12%' : ageDays <= 7 ? '+7%' : '+3%';
          const score = supporti * 3 + (priorityWeight[row.priorita ?? 'media'] ?? 2) * 2 + (severityWeight[row.severita ?? 'media'] ?? 2);

          return {
            id: row.id,
            titolo: row.titolo,
            categoria: categoryById[row.category_id] ?? 'Generale',
            supporti,
            trend,
            score
          };
        })
        .sort((a: any, b: any) => b.score - a.score)
        .slice(0, q.data.limit)
        .map(({ score, ...item }: any) => item);

      return { items };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/notifications', async (req, reply) => {
    const q = notificationsQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

    try {
      const [timelineRes, segnalazioniRes] = await Promise.all([
        rest.get('/segnalazione_timeline_events', {
          params: {
            select: 'id,segnalazione_id,event_type,message,created_at,tenant_id',
            tenant_id: `eq.${q.data.tenant_id}`,
            order: 'created_at.desc',
            limit: '250'
          }
        }),
        rest.get('/segnalazioni', {
          params: {
            select: 'id,titolo,created_by,reported_by,user_id,author_id,assigned_to,tenant_id,stato',
            tenant_id: `eq.${q.data.tenant_id}`,
            limit: '250'
          }
        })
      ]);

      const segnalazioni = (segnalazioniRes.data ?? []) as Array<Record<string, any>>;
      const byId = segnalazioni.reduce<Record<string, Record<string, any>>>((acc, row) => {
        if (row.id) acc[String(row.id)] = row;
        return acc;
      }, {});

      const timelineRows = (timelineRes.data ?? []) as Array<Record<string, any>>;
      const filtered = timelineRows.filter((row) => {
        const segnalazione = byId[String(row.segnalazione_id ?? '')];
        if (!segnalazione) return false;
        if (!q.data.user_id) return true;
        const uid = q.data.user_id;
        return [segnalazione.created_by, segnalazione.reported_by, segnalazione.user_id, segnalazione.author_id, segnalazione.assigned_to]
          .filter(Boolean)
          .includes(uid);
      });

      const mapped = filtered.map((row, idx) => {
        const segnalazione = byId[String(row.segnalazione_id)] ?? {};
        const eventType = String(row.event_type ?? '').toLowerCase();
        const kind = eventType.includes('assign') ? 'assignment' : eventType.includes('status') ? 'status' : 'update';
        return {
          id: String(row.id ?? `${row.segnalazione_id}-${idx}`),
          kind,
          title: kind === 'assignment'
            ? `Assegnazione segnalazione ${segnalazione.id ?? row.segnalazione_id}`
            : kind === 'status'
              ? `Aggiornamento segnalazione ${segnalazione.id ?? row.segnalazione_id}`
              : `Nuovo aggiornamento ${segnalazione.id ?? row.segnalazione_id}`,
          body: row.message ?? segnalazione.titolo ?? 'Aggiornamento disponibile',
          timestamp: row.created_at ?? new Date().toISOString(),
          unread: idx < 3
        };
      });

      const offset = (q.data.page - 1) * q.data.page_size;
      return { items: mapped.slice(offset, offset + q.data.page_size), page: q.data.page, page_size: q.data.page_size };
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
      if (q.data.search) params.or = `(titolo.ilike.*${q.data.search}*,descrizione.ilike.*${q.data.search}*)`;

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

  app.post('/v1/admin/segnalazioni/:id/status-transition', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'tenant_admin');
    if (!access) return;

    const p = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, p)) return;
    const body = statusTransitionSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    if (!access.isGlobalAdmin && access.tenantId !== body.data.tenant_id) {
      return reply.code(403).send({ error: 'Cannot update another tenant segnalazione' });
    }

    try {
      const segnalazione = await ensureSegnalazioneTenant(rest, p.data.id, body.data.tenant_id);
      if (!segnalazione) return reply.code(404).send({ error: 'Segnalazione not found for tenant' });

      const currentStatus = segnalazione.stato ?? 'in_attesa';
      const allowed = allowedTransitions[currentStatus] ?? [];
      if (!allowed.includes(body.data.status)) {
        return reply.code(409).send({ error: `Transition ${currentStatus} -> ${body.data.status} not allowed` });
      }

      const { data } = await rest.patch('/segnalazioni', { stato: body.data.status }, {
        params: { id: `eq.${p.data.id}`, tenant_id: `eq.${body.data.tenant_id}` },
        headers: { Prefer: 'return=representation' }
      });

      await createAdminTrail(rest, {
        tenantId: body.data.tenant_id,
        segnalazioneId: p.data.id,
        actorId: access.userId,
        eventType: 'status_transition',
        message: body.data.message ?? `Stato aggiornato a ${body.data.status}`,
        payload: { from: currentStatus, to: body.data.status },
        action: 'segnalazione_status_transition',
        metadata: { from: currentStatus, to: body.data.status }
      });

      return { item: data?.[0] ?? { id: p.data.id, stato: body.data.status } };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/admin/segnalazioni/:id/assign', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'tenant_admin');
    if (!access) return;

    const p = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, p)) return;
    const body = assignSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    if (!access.isGlobalAdmin && access.tenantId !== body.data.tenant_id) {
      return reply.code(403).send({ error: 'Cannot update another tenant segnalazione' });
    }

    try {
      const segnalazione = await ensureSegnalazioneTenant(rest, p.data.id, body.data.tenant_id);
      if (!segnalazione) return reply.code(404).send({ error: 'Segnalazione not found for tenant' });

      const { data } = await rest.patch('/segnalazioni', { assigned_to: body.data.assigned_to }, {
        params: { id: `eq.${p.data.id}`, tenant_id: `eq.${body.data.tenant_id}` },
        headers: { Prefer: 'return=representation' }
      });

      await createAdminTrail(rest, {
        tenantId: body.data.tenant_id,
        segnalazioneId: p.data.id,
        actorId: access.userId,
        eventType: 'assigned',
        message: body.data.message ?? 'Segnalazione assegnata ad operatore',
        payload: { assigned_to: body.data.assigned_to },
        action: 'segnalazione_assigned',
        metadata: { assigned_to: body.data.assigned_to }
      });

      return { item: data?.[0] ?? { id: p.data.id, assigned_to: body.data.assigned_to } };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/admin/segnalazioni/:id/public-response', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'tenant_admin');
    if (!access) return;

    const p = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, p)) return;
    const body = publicResponseSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    if (!access.isGlobalAdmin && access.tenantId !== body.data.tenant_id) {
      return reply.code(403).send({ error: 'Cannot update another tenant segnalazione' });
    }

    try {
      const segnalazione = await ensureSegnalazioneTenant(rest, p.data.id, body.data.tenant_id);
      if (!segnalazione) return reply.code(404).send({ error: 'Segnalazione not found for tenant' });

      const currentMetadata = segnalazione.metadata ?? {};
      const nextMetadata = {
        ...currentMetadata,
        latest_public_response: {
          message: body.data.message,
          actor_id: access.userId,
          created_at: new Date().toISOString()
        }
      };

      await rest.patch('/segnalazioni', { public_response: body.data.message, metadata: nextMetadata }, {
        params: { id: `eq.${p.data.id}`, tenant_id: `eq.${body.data.tenant_id}` },
        headers: { Prefer: 'return=minimal' }
      });

      await createAdminTrail(rest, {
        tenantId: body.data.tenant_id,
        segnalazioneId: p.data.id,
        actorId: access.userId,
        eventType: 'public_response',
        message: body.data.message,
        payload: { public: true },
        action: 'segnalazione_public_response',
        metadata: { message_preview: body.data.message.slice(0, 120) }
      });

      return { ok: true };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/admin/segnalazioni/:id/moderation-flags', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'tenant_admin');
    if (!access) return;

    const p = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, p)) return;
    const body = moderationFlagsSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    if (!access.isGlobalAdmin && access.tenantId !== body.data.tenant_id) {
      return reply.code(403).send({ error: 'Cannot update another tenant segnalazione' });
    }

    try {
      const segnalazione = await ensureSegnalazioneTenant(rest, p.data.id, body.data.tenant_id);
      if (!segnalazione) return reply.code(404).send({ error: 'Segnalazione not found for tenant' });

      const nextFlags = {
        ...(segnalazione.moderation_flags ?? {}),
        ...body.data.flags,
        updated_by: access.userId,
        updated_at: new Date().toISOString()
      };

      await rest.patch('/segnalazioni', { moderation_flags: nextFlags }, {
        params: { id: `eq.${p.data.id}`, tenant_id: `eq.${body.data.tenant_id}` },
        headers: { Prefer: 'return=minimal' }
      });

      await createAdminTrail(rest, {
        tenantId: body.data.tenant_id,
        segnalazioneId: p.data.id,
        actorId: access.userId,
        eventType: 'moderation_flags',
        message: 'Flag di moderazione aggiornati',
        payload: { flags: nextFlags },
        action: 'segnalazione_moderation_flags',
        metadata: { flags: nextFlags }
      });

      return { ok: true, moderation_flags: nextFlags };
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

  app.get('/v1/segnalazioni/assisted-tags', async (req, reply) => {
    const q = assistedTagsQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

    try {
      const { data } = await rest.get('/tenant_tag_catalog', {
        params: {
          select: 'id,slug,label,sort_order',
          tenant_id: `eq.${q.data.tenant_id}`,
          is_active: 'eq.true',
          order: 'sort_order.asc,label.asc',
          limit: String(q.data.limit)
        }
      });

      const query = q.data.q ? normalizeText(q.data.q) : '';
      const items = (data ?? []).filter((row: any) => {
        if (!query) return true;
        return normalizeText(`${row.label ?? ''} ${row.slug ?? ''}`).includes(query);
      });

      return { items };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/segnalazioni/assisted-addresses', async (req, reply) => {
    const q = assistedAddressQuerySchema.safeParse(req.query);
    if (isInvalid(reply, q)) return;

    try {
      const { data } = await rest.get('/tenant_address_catalog', {
        params: {
          select: 'id,address,reference_code,lat,lng',
          tenant_id: `eq.${q.data.tenant_id}`,
          is_active: 'eq.true',
          order: 'address.asc',
          limit: '200'
        }
      });

      const query = normalizeText(q.data.q);
      const items = (data ?? [])
        .filter((row: any) => normalizeText(`${row.address ?? ''} ${row.reference_code ?? ''}`).includes(query))
        .slice(0, q.data.limit);

      return { items };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/segnalazioni/assisted-addresses/validate', async (req, reply) => {
    const body = assistedAddressValidateSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    try {
      const { data } = await rest.get('/tenant_address_catalog', {
        params: {
          select: 'id,address,reference_code,lat,lng,source_dataset',
          tenant_id: `eq.${body.data.tenant_id}`,
          id: `eq.${body.data.catalog_id}`,
          is_active: 'eq.true',
          limit: '1'
        }
      });

      const found = data?.[0];
      if (!found) return reply.code(404).send({ error: 'Address reference not found for tenant' });

      const valid = normalizeText(found.address ?? '') === normalizeText(body.data.address);
      if (!valid) {
        return reply.code(422).send({
          error: 'Address validation failed: selected suggestion does not match input address.'
        });
      }

      return {
        validated: true,
        source: 'tenant_address_catalog',
        catalog_id: found.id,
        normalized_address: found.address,
        reference_code: found.reference_code,
        lat: Number(found.lat),
        lng: Number(found.lng),
        confidence: 1,
        dataset: found.source_dataset ?? 'local'
      };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.post('/v1/segnalazioni/wizard', async (req, reply) => {
    const body = wizardPayloadSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    try {
      const requestedTagSlugs = Array.from(new Set((body.data.tag_slugs ?? body.data.tags ?? []).map((tag) => tag.trim().toLowerCase()).filter(Boolean)));
      const addressValidation = body.data.address_validation;
      const strictAddressValidation = isAddressValidationStrict();

      if (strictAddressValidation && (!addressValidation || !addressValidation.validated)) {
        return reply.code(422).send({
          error: 'Address must be validated before submit. Seleziona un suggerimento e conferma validazione indirizzo.'
        });
      }

      const [tagsRes, validatedAddressRes] = await Promise.all([
        requestedTagSlugs.length > 0
          ? rest.get('/tenant_tag_catalog', {
            params: {
              select: 'slug,label',
              tenant_id: `eq.${body.data.tenant_id}`,
              is_active: 'eq.true',
              slug: `in.(${requestedTagSlugs.map((slug) => `"${slug.replace(/"/g, '')}"`).join(',')})`
            }
          })
          : Promise.resolve({ data: [] as Array<{ slug: string; label: string }> }),
        addressValidation?.catalog_id
          ? rest.get('/tenant_address_catalog', {
            params: {
              select: 'id,address,reference_code,lat,lng,source_dataset',
              tenant_id: `eq.${body.data.tenant_id}`,
              id: `eq.${addressValidation.catalog_id}`,
              is_active: 'eq.true',
              limit: '1'
            }
          })
          : Promise.resolve({ data: [] as Array<Record<string, unknown>> })
      ]);

      const allowedTags = (tagsRes.data ?? []).map((row: any) => row.slug).filter(Boolean);
      if (allowedTags.length !== requestedTagSlugs.length) {
        return reply.code(422).send({ error: 'One or more selected tags are not allowed for this tenant.' });
      }

      const validatedAddress = validatedAddressRes.data?.[0] as any;
      if (strictAddressValidation && !validatedAddress) {
        return reply.code(422).send({ error: 'Address validation missing or expired. Ripetere la verifica indirizzo.' });
      }

      const finalAddress = validatedAddress?.address ?? body.data.address;
      const finalLat = validatedAddress?.lat !== undefined ? Number(validatedAddress.lat) : body.data.lat;
      const finalLng = validatedAddress?.lng !== undefined ? Number(validatedAddress.lng) : body.data.lng;

      const createdPayload = {
        tenant_id: body.data.tenant_id,
        codice: codiceSegnalazione(),
        titolo: body.data.titolo,
        descrizione: body.data.descrizione,
        category_id: body.data.category_id,
        neighborhood_id: body.data.neighborhood_id,
        address: finalAddress,
        lat: finalLat,
        lng: finalLng,
        attachments: body.data.attachments ?? [],
        tags: allowedTags,
        metadata: {
          ...(body.data.metadata ?? {}),
          address_validation: validatedAddress
            ? {
              validated: true,
              source: 'tenant_address_catalog',
              catalog_id: validatedAddress.id,
              normalized_address: validatedAddress.address,
              reference_code: validatedAddress.reference_code,
              lat: Number(validatedAddress.lat),
              lng: Number(validatedAddress.lng),
              dataset: validatedAddress.source_dataset ?? 'local',
              confidence: addressValidation?.confidence ?? 1
            }
            : { validated: false, mode: strictAddressValidation ? 'strict' : 'soft' }
        },
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

  app.post('/v1/bug-reports', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'authenticated');
    if (!access) return;

    const body = bugReportSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    try {
      const { data: created } = await rest.post('/bug_reports', {
        tenant_id: access.tenantId,
        reported_by: access.userId,
        title: body.data.title,
        description: body.data.description,
        page_url: body.data.page_url
      }, { headers: { Prefer: 'return=representation' } });

      const bug = created?.[0];
      if (!bug?.id) return reply.code(500).send({ error: 'Unable to create bug report' });

      const { data: admins } = await rest.get('/user_roles', {
        params: { select: 'user_id,roles(code),user_profiles(email,tenant_id)' }
      });

      const recipients: EmailNotificationRecipient[] = (admins ?? []).flatMap((row: any) => {
        const code = row.roles?.code;
        const email = row.user_profiles?.email;
        const tenantMatch = row.user_profiles?.tenant_id === access.tenantId;
        if (!email || !(code === 'super_admin' || (code === 'tenant_admin' && tenantMatch))) return [];
        return [{ userId: row.user_id, email }];
      });

      await Promise.all(recipients.map((admin) => queueAdminEmailNotification(rest, admin, {
        bugReportId: bug.id,
        tenantId: access.tenantId,
        reporterId: access.userId,
        title: body.data.title,
        description: body.data.description,
        pageUrl: body.data.page_url
      })));

      return reply.code(201).send({ id: bug.id, notified_admins: recipients.length });
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/docs/public', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'authenticated');
    if (!access) return;

    try {
      const [globalRes, tenantRes] = await Promise.all([
        rest.get('/global_docs', { params: { select: 'id,slug,title,content_md,sort_order', is_published: 'eq.true', order: 'sort_order.asc' } }),
        rest.get('/tenant_docs', { params: { select: 'id,slug,title,content_md,sort_order', tenant_id: `eq.${access.tenantId}`, is_published: 'eq.true', order: 'sort_order.asc' } })
      ]);

      return { global: globalRes.data ?? [], tenant: tenantRes.data ?? [] };
    } catch (error: any) {
      return reply.code(500).send({ error: error.message });
    }
  });

  app.get('/v1/admin/docs/global', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'global_admin');
    if (!access) return;
    const { data } = await rest.get('/global_docs', { params: { select: '*', order: 'sort_order.asc' } });
    return { items: data ?? [] };
  });

  app.post('/v1/admin/docs/global', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'global_admin');
    if (!access) return;
    const body = docSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    const { data } = await rest.post('/global_docs', { ...body.data, updated_by: access.userId }, {
      params: { on_conflict: 'slug' },
      headers: { Prefer: 'resolution=merge-duplicates,return=representation' }
    });

    return reply.code(201).send(data?.[0] ?? body.data);
  });

  app.get('/v1/admin/docs/tenant/:id', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'tenant_admin');
    if (!access) return;

    const params = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, params)) return;

    if (!access.isGlobalAdmin && access.tenantId !== params.data.id) {
      return reply.code(403).send({ error: 'Cannot manage another tenant documentation' });
    }

    const { data } = await rest.get('/tenant_docs', { params: { select: '*', tenant_id: `eq.${params.data.id}`, order: 'sort_order.asc' } });
    return { items: data ?? [] };
  });

  app.post('/v1/admin/docs/tenant/:id', async (req, reply) => {
    const access = await requireAccess(req, reply, rest, 'tenant_admin');
    if (!access) return;

    const params = idParamSchema.safeParse(req.params);
    if (isInvalid(reply, params)) return;
    const body = docSchema.safeParse(req.body);
    if (isInvalid(reply, body)) return;

    if (!access.isGlobalAdmin && access.tenantId !== params.data.id) {
      return reply.code(403).send({ error: 'Cannot manage another tenant documentation' });
    }

    const { data } = await rest.post('/tenant_docs', { ...body.data, tenant_id: params.data.id, updated_by: access.userId }, {
      params: { on_conflict: 'tenant_id,slug' },
      headers: { Prefer: 'resolution=merge-duplicates,return=representation' }
    });

    return reply.code(201).send(data?.[0] ?? body.data);
  });

  return app;
}
