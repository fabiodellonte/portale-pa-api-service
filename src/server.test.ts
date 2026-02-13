import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type AuthClient, type RestClient } from './server.js';

function mockRest(): RestClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn()
  } as unknown as RestClient;
}

function mockAuth(): AuthClient {
  return {
    request: vi.fn()
  } as unknown as AuthClient;
}

describe('api server', () => {
  afterEach(() => vi.restoreAllMocks());

  it('returns tenants list', async () => {
    const rest = mockRest();
    vi.mocked(rest.get).mockResolvedValue({ data: [{ id: '1', name: 'Comune Test' }] });

    const app = await buildServer(rest);
    const response = await app.inject({ method: 'GET', url: '/v1/tenants' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ items: [{ id: '1', name: 'Comune Test' }] });
    await app.close();
  });

  it('rejects /v1/me/preferences without auth headers', async () => {
    const rest = mockRest();
    const app = await buildServer(rest);

    const response = await app.inject({ method: 'GET', url: '/v1/me/preferences' });

    expect(response.statusCode).toBe(401);
    await app.close();
  });

  it('updates language preference with zod validation', async () => {
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
    expect(response.json()).toMatchObject({ language: 'en' });
    await app.close();
  });

  it('blocks branding update to regular users', async () => {
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

  it('allows tenant admin branding update', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'u1', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'tenant_admin' } }] });
    vi.mocked(rest.post).mockResolvedValue({ data: [{ tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0', primary_color: '#0055A4', secondary_color: '#FFFFFF' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/tenants/1386f06c-8d0c-4a99-a157-d3576447add0/branding',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' },
      payload: { primary_color: '#0055A4', secondary_color: '#FFFFFF' }
    });

    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('allows global admin role assignment', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'admin', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'super_admin' } }] })
      .mockResolvedValueOnce({ data: [{ id: 'u2', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ id: 'r1', code: 'tenant_admin' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/admin/roles/1386f06c-8d0c-4a99-a157-d3576447add2',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' },
      payload: { tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0', role_code: 'tenant_admin' }
    });

    expect(response.statusCode).toBe(200);
    expect(rest.post).toHaveBeenCalled();
    await app.close();
  });

  it('returns public metrics', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 's1', stato: 'in_attesa' }, { id: 's2', stato: 'chiusa' }] })
      .mockResolvedValueOnce({ data: [{ id: 'v1' }, { id: 'v2' }] })
      .mockResolvedValueOnce({ data: [{ id: 'f1' }] });

    const app = await buildServer(rest);
    const response = await app.inject({ method: 'GET', url: '/v1/public/metrics?tenant_id=1386f06c-8d0c-4a99-a157-d3576447add0' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ total_segnalazioni: 2, total_votes: 2, total_follows: 1, by_status: { in_attesa: 1, chiusa: 1 } });
    await app.close();
  });

  it('returns ranking transparency metadata', async () => {
    const app = await buildServer(mockRest());
    const response = await app.inject({ method: 'GET', url: '/v1/public/transparency/ranking' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ algorithm: 'weighted_sum', normalized: true });
    await app.close();
  });

  it('proxies auth calls through /v1/auth/*', async () => {
    const rest = mockRest();
    const auth = mockAuth();
    vi.mocked(auth.request).mockResolvedValue({ status: 200, data: { access_token: 'x' } } as any);

    const app = await buildServer(rest, auth);
    const response = await app.inject({ method: 'POST', url: '/v1/auth/token?grant_type=password', payload: { email: 'user@test.com' } });

    expect(response.statusCode).toBe(200);
    expect(auth.request).toHaveBeenCalledWith(expect.objectContaining({ url: '/token', method: 'POST' }));
    await app.close();
  });

  it('supports admin segnalazione status transition', async () => {
    const rest = mockRest();
    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: 'admin', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0' }] })
      .mockResolvedValueOnce({ data: [{ roles: { code: 'tenant_admin' } }] })
      .mockResolvedValueOnce({ data: [{ id: 's1', tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0', stato: 'in_attesa' }] });
    vi.mocked(rest.patch).mockResolvedValue({ data: [{ id: 's1', stato: 'presa_in_carico' }] });
    vi.mocked(rest.post).mockResolvedValue({ data: [] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/admin/segnalazioni/1386f06c-8d0c-4a99-a157-d3576447add9/status-transition',
      headers: { 'x-user-id': '1386f06c-8d0c-4a99-a157-d3576447add1', 'x-tenant-id': '1386f06c-8d0c-4a99-a157-d3576447add0' },
      payload: { tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0', status: 'presa_in_carico' }
    });

    expect(response.statusCode).toBe(200);
    expect(rest.patch).toHaveBeenCalled();
    await app.close();
  });
});
