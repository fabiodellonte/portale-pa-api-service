import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type RestClient } from './server.js';

const TENANT_A = '1386f06c-8d0c-4a99-a157-d3576447add0';
const TENANT_B = '2386f06c-8d0c-4a99-a157-d3576447add0';
const USER_ID = '1386f06c-8d0c-4a99-a157-d3576447add1';
const SEGNALAZIONE_ID = '3386f06c-8d0c-4a99-a157-d3576447add0';

type RoleCode = 'super_admin' | 'tenant_admin' | 'operatore' | 'cittadino' | 'admin' | 'maintainer' | 'citizen';

function mockRest(): RestClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn()
  } as unknown as RestClient;
}

function authHeaders(tenantId = TENANT_A, userId = USER_ID) {
  return { 'x-user-id': userId, 'x-tenant-id': tenantId };
}

function primeAccess(rest: RestClient, role: RoleCode, profileTenant = TENANT_A) {
  vi.mocked(rest.get)
    .mockResolvedValueOnce({ data: [{ id: USER_ID, tenant_id: profileTenant }] })
    .mockResolvedValueOnce({ data: [{ roles: { code: role } }] });
}

describe('api server auth + tenant authorization guardrails', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.ENABLE_DEMO_MODE_SWITCH;
  });

  it('returns 401 on protected endpoints when auth headers are missing', async () => {
    const rest = mockRest();
    const app = await buildServer(rest);

    const checks = await Promise.all([
      app.inject({ method: 'PUT', url: '/v1/me/preferences/language', payload: { language: 'en' } }),
      app.inject({ method: 'POST', url: '/v1/bug-reports', payload: { title: 'Bug serio', description: 'Descrizione bug abbastanza lunga' } }),
      app.inject({ method: 'GET', url: '/v1/docs/public' }),
      app.inject({ method: 'POST', url: '/v1/admin/docs/global', payload: { slug: 'faq', title: 'FAQ', content_md: 'contenuto di prova sufficiente', is_published: true, sort_order: 1 } }),
      app.inject({ method: 'POST', url: `/v1/admin/segnalazioni/${SEGNALAZIONE_ID}/assign`, payload: { tenant_id: TENANT_A, assigned_to: USER_ID } })
    ]);

    checks.forEach((response) => expect(response.statusCode).toBe(401));
    expect(rest.get).not.toHaveBeenCalled();

    await app.close();
  });

  it('blocks tenant mismatch on key tenant-admin phase3/4 routes', async () => {
    const routes = [
      {
        url: `/v1/tenants/${TENANT_B}/branding`,
        method: 'PUT' as const,
        payload: { primary_color: '#0055A4', secondary_color: '#FFFFFF' }
      },
      {
        url: `/v1/admin/docs/tenant/${TENANT_B}`,
        method: 'POST' as const,
        payload: { slug: 'regole', title: 'Regole', content_md: 'contenuto locale tenant valido', is_published: true, sort_order: 1 }
      },
      {
        url: `/v1/admin/segnalazioni/${SEGNALAZIONE_ID}/status-transition`,
        method: 'POST' as const,
        payload: { tenant_id: TENANT_B, status: 'presa_in_carico' }
      },
      {
        url: `/v1/admin/segnalazioni/${SEGNALAZIONE_ID}/assign`,
        method: 'POST' as const,
        payload: { tenant_id: TENANT_B, assigned_to: USER_ID }
      },
      {
        url: `/v1/admin/segnalazioni/${SEGNALAZIONE_ID}/public-response`,
        method: 'POST' as const,
        payload: { tenant_id: TENANT_B, message: 'Aggiornamento pubblico' }
      },
      {
        url: `/v1/admin/segnalazioni/${SEGNALAZIONE_ID}/moderation-flags`,
        method: 'POST' as const,
        payload: { tenant_id: TENANT_B, flags: { hidden: true } }
      }
    ];

    for (const route of routes) {
      const rest = mockRest();
      primeAccess(rest, 'tenant_admin', TENANT_A);
      const app = await buildServer(rest);

      const response = await app.inject({
        method: route.method,
        url: route.url,
        headers: authHeaders(TENANT_A),
        payload: route.payload
      });

      expect(response.statusCode).toBe(403);
      await app.close();
    }
  });

  it('denies global-admin only endpoints to tenant_admin and cittadino', async () => {
    for (const role of ['tenant_admin', 'cittadino'] as const) {
      const rest = mockRest();
      primeAccess(rest, role, TENANT_A);
      const app = await buildServer(rest);

      const globalDocs = await app.inject({
        method: 'POST',
        url: '/v1/admin/docs/global',
        headers: authHeaders(TENANT_A),
        payload: { slug: 'faq', title: 'FAQ', content_md: 'contenuto di prova sufficiente', is_published: true, sort_order: 1 }
      });

      expect(globalDocs.statusCode).toBe(403);

      await app.close();
    }
  });

  it('keeps existing happy path coverage for phase4 protected endpoints', async () => {
    const rest = mockRest();
    primeAccess(rest, 'cittadino', TENANT_A);
    vi.mocked(rest.patch).mockResolvedValue({ data: [{ language: 'en' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/me/preferences/language',
      headers: authHeaders(TENANT_A),
      payload: { language: 'en' }
    });

    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('creates bug report and queues admin email notifications', async () => {
    const rest = mockRest();
    primeAccess(rest, 'cittadino', TENANT_A);
    vi.mocked(rest.get).mockResolvedValueOnce({
      data: [
        { user_id: 'a1', roles: { code: 'super_admin' }, user_profiles: { email: 'ga@example.com', tenant_id: 'xxx' } },
        { user_id: 'a2', roles: { code: 'tenant_admin' }, user_profiles: { email: 'ta@example.com', tenant_id: TENANT_A } }
      ]
    });
    vi.mocked(rest.post)
      .mockResolvedValueOnce({ data: [{ id: 'b1' }] })
      .mockResolvedValue({ data: [{ id: 'n1' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/bug-reports',
      headers: authHeaders(TENANT_A),
      payload: { title: 'Errore invio pratica', description: 'Il pulsante invia non risponde nella pagina pratiche.' }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({ id: 'b1', notified_admins: 2 });
    await app.close();
  });

  it('returns docs for authenticated user and allows global admin upsert', async () => {
    const userRest = mockRest();
    primeAccess(userRest, 'cittadino', TENANT_A);
    vi.mocked(userRest.get)
      .mockResolvedValueOnce({ data: [{ slug: 'how-to', title: 'Guida' }] })
      .mockResolvedValueOnce({ data: [{ slug: 'tenant', title: 'Guida Comune' }] });

    const userApp = await buildServer(userRest);
    const docs = await userApp.inject({ method: 'GET', url: '/v1/docs/public', headers: authHeaders(TENANT_A) });
    expect(docs.statusCode).toBe(200);
    expect(docs.json().global).toHaveLength(1);
    await userApp.close();

    const adminRest = mockRest();
    primeAccess(adminRest, 'super_admin', TENANT_A);
    vi.mocked(adminRest.post).mockResolvedValue({ data: [{ slug: 'faq', title: 'FAQ' }] });

    const adminApp = await buildServer(adminRest);
    const upsert = await adminApp.inject({
      method: 'POST',
      url: '/v1/admin/docs/global',
      headers: authHeaders(TENANT_A),
      payload: { slug: 'faq', title: 'FAQ', content_md: 'contenuto di prova sufficiente', is_published: true, sort_order: 1 }
    });

    expect(upsert.statusCode).toBe(201);
    await adminApp.close();
  });

  it('maps legacy roles to new portal roles on /v1/me/access', async () => {
    const rest = mockRest();
    primeAccess(rest, 'tenant_admin', TENANT_A);
    const app = await buildServer(rest);

    const response = await app.inject({ method: 'GET', url: '/v1/me/access', headers: authHeaders(TENANT_A) });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      portal_role: 'maintainer',
      portal_roles: ['maintainer', 'citizen']
    });
    await app.close();
  });

  it('blocks demo-mode endpoints when feature flag is disabled', async () => {
    const rest = mockRest();
    primeAccess(rest, 'super_admin', TENANT_A);
    const app = await buildServer(rest, undefined as any, {
      demoModeExecutor: vi.fn().mockResolvedValue({ state: 'off', output: 'disabled' })
    });

    const response = await app.inject({ method: 'GET', url: '/v1/admin/demo-mode', headers: authHeaders(TENANT_A) });

    expect(response.statusCode).toBe(404);
    await app.close();
  });

  it('allows only global admin on demo-mode endpoints', async () => {
    process.env.ENABLE_DEMO_MODE_SWITCH = 'true';

    const rest = mockRest();
    primeAccess(rest, 'tenant_admin', TENANT_A);
    const app = await buildServer(rest, undefined as any, {
      demoModeExecutor: vi.fn().mockResolvedValue({ state: 'off', output: 'ok' })
    });

    const response = await app.inject({ method: 'GET', url: '/v1/admin/demo-mode', headers: authHeaders(TENANT_A) });

    expect(response.statusCode).toBe(403);
    await app.close();
  });

  it('reads and toggles demo-mode when enabled for global admin', async () => {
    process.env.ENABLE_DEMO_MODE_SWITCH = 'true';

    const rest = mockRest();
    primeAccess(rest, 'super_admin', TENANT_A);
    primeAccess(rest, 'super_admin', TENANT_A);
    const demoModeExecutor = vi.fn()
      .mockResolvedValueOnce({ state: 'off', output: 'status off' })
      .mockResolvedValueOnce({ state: 'on', output: 'DEMO mode ON' })
      .mockResolvedValueOnce({ state: 'on', output: 'status on' });

    const app = await buildServer(rest, undefined as any, { demoModeExecutor });

    const statusResponse = await app.inject({ method: 'GET', url: '/v1/admin/demo-mode', headers: authHeaders(TENANT_A) });
    expect(statusResponse.statusCode).toBe(200);
    expect(statusResponse.json()).toMatchObject({ state: 'off' });

    const toggleResponse = await app.inject({ method: 'POST', url: '/v1/admin/demo-mode', headers: authHeaders(TENANT_A), payload: { mode: 'on' } });
    expect(toggleResponse.statusCode).toBe(200);
    expect(toggleResponse.json()).toMatchObject({ requested_mode: 'on', state: 'on' });
    expect(demoModeExecutor).toHaveBeenNthCalledWith(1, 'status');
    expect(demoModeExecutor).toHaveBeenNthCalledWith(2, 'on');
    expect(demoModeExecutor).toHaveBeenNthCalledWith(3, 'status');

    await app.close();
  });

  it('returns duplicate candidates from dedicated endpoint', async () => {
    const rest = mockRest();
    vi.mocked(rest.get).mockResolvedValue({ data: [{ id: 's1', titolo: 'Buca via Roma' }] });
    const app = await buildServer(rest);

    const response = await app.inject({ method: 'GET', url: `/v1/segnalazioni/duplicates?tenant_id=${TENANT_A}&titolo=Buca%20Roma` });

    expect(response.statusCode).toBe(200);
    expect(response.json().items).toHaveLength(1);
    await app.close();
  });

  it('returns computed priorities from DB-backed datasets', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 's1', titolo: 'Buca via Roma', priorita: 'alta', severita: 'media', category_id: 'c1', updated_at: new Date().toISOString() }] })
      .mockResolvedValueOnce({ data: [{ segnalazione_id: 's1' }, { segnalazione_id: 's1' }] })
      .mockResolvedValueOnce({ data: [{ id: 'c1', name: 'Viabilità' }] });

    const app = await buildServer(rest);
    const response = await app.inject({ method: 'GET', url: `/v1/segnalazioni/priorities?tenant_id=${TENANT_A}&limit=5` });

    expect(response.statusCode).toBe(200);
    expect(response.json().items[0]).toMatchObject({ titolo: 'Buca via Roma', categoria: 'Viabilità', supporti: 2 });
    await app.close();
  });
});
