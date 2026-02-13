import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type RestClient } from './server.js';

function mockRest(): RestClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn()
  } as unknown as RestClient;
}

describe('api server phase 4 + docs/bug flow', () => {
  afterEach(() => vi.restoreAllMocks());

  it('updates language preference', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'u1', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'cittadino' } }] });
    vi.mocked(rest.patch).mockResolvedValue({ data: [{ language: 'en' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/me/preferences/language',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' },
      payload: { language: 'en' }
    });

    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('denies branding update to regular user', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'u1', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'cittadino' } }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/tenants/1386f06c-8d0c-4a99-a157-d3576447add0/branding',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' },
      payload: { primary_color: '#0055A4', secondary_color: '#FFFFFF' }
    });

    expect(response.statusCode).toBe(403);
    await app.close();
  });

  it('creates bug report and queues admin email notifications', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'u1', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'cittadino' } }] })
      .mockResolvedValueOnce({
        data: [
          { user_id: 'a1', roles: { code: 'super_admin' }, user_profiles: { email: 'ga@example.com', tenant_id: 'xxx' } },
          { user_id: 'a2', roles: { code: 'tenant_admin' }, user_profiles: { email: 'ta@example.com', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' } }
        ]
      });
    vi.mocked(rest.post)
      .mockResolvedValueOnce({ data: [{ id: 'b1' }] })
      .mockResolvedValue({ data: [{ id: 'n1' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/bug-reports',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' },
      payload: { title: 'Errore invio pratica', description: 'Il pulsante invia non risponde nella pagina pratiche.' }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({ id: 'b1', notified_admins: 2 });
    await app.close();
  });

  it('returns public docs for authenticated user', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'u1', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'cittadino' } }] })
      .mockResolvedValueOnce({ data: [{ slug: 'how-to', title: 'Guida' }] })
      .mockResolvedValueOnce({ data: [{ slug: 'tenant', title: 'Guida Comune' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'GET',
      url: '/v1/docs/public',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().global).toHaveLength(1);
    await app.close();
  });

  it('allows global admin to upsert global docs', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'admin', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'super_admin' } }] });
    vi.mocked(rest.post).mockResolvedValue({ data: [{ slug: 'faq', title: 'FAQ' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/admin/docs/global',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' },
      payload: { slug: 'faq', title: 'FAQ', content_md: 'contenuto di prova sufficiente', is_published: true, sort_order: 1 }
    });

    expect(response.statusCode).toBe(201);
    await app.close();
  });

  it('denies tenant admin on foreign tenant docs', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'admin', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'tenant_admin' } }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/admin/docs/tenant/2386f06c-8d0c-4a99-a157-d3576447add0',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' },
      payload: { slug: 'regole', title: 'Regole', content_md: 'contenuto locale tenant valido', is_published: true, sort_order: 1 }
    });

    expect(response.statusCode).toBe(403);
    await app.close();
  });
});
