import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type RestClient } from './server.js';

function mockRest(): RestClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn()
  } as unknown as RestClient;
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

  it('creates tenant', async () => {
    const rest = mockRest();
    vi.mocked(rest.post).mockResolvedValue({ data: [{ id: 'abc', name: 'Comune Nuovo' }] });

    const app = await buildServer(rest);
    const response = await app.inject({ method: 'POST', url: '/v1/tenants', payload: { name: 'Comune Nuovo' } });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({ id: 'abc', name: 'Comune Nuovo' });

    await app.close();
  });

  it('deletes tenant by id', async () => {
    const rest = mockRest();
    vi.mocked(rest.delete).mockResolvedValue({ data: null });
    const id = '1386f06c-8d0c-4a99-a157-d3576447add0';

    const app = await buildServer(rest);
    const response = await app.inject({ method: 'DELETE', url: `/v1/tenants/${id}` });

    expect(response.statusCode).toBe(204);
    expect(rest.delete).toHaveBeenCalled();

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
    expect(response.json()).toMatchObject({
      total_segnalazioni: 2,
      total_votes: 2,
      total_follows: 1,
      by_status: { in_attesa: 1, chiusa: 1 }
    });

    await app.close();
  });

  it('filters segnalazioni list', async () => {
    const rest = mockRest();
    vi.mocked(rest.get).mockResolvedValue({ data: [{ id: 's1', titolo: 'Buca in strada' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'GET',
      url: '/v1/segnalazioni?tenant_id=1386f06c-8d0c-4a99-a157-d3576447add0&search=buca&page=1&page_size=10'
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().items).toHaveLength(1);
    expect(rest.get).toHaveBeenCalledWith('/segnalazioni', expect.objectContaining({ params: expect.objectContaining({ tenant_id: 'eq.1386f06c-8d0c-4a99-a157-d3576447add0' }) }));

    await app.close();
  });

  it('toggles vote on segnalazione', async () => {
    const rest = mockRest();
    const tenantId = '1386f06c-8d0c-4a99-a157-d3576447add0';
    const segnalazioneId = '2386f06c-8d0c-4a99-a157-d3576447add0';
    const userId = '3386f06c-8d0c-4a99-a157-d3576447add0';

    vi.mocked(rest.get)
      .mockResolvedValueOnce({ data: [{ id: segnalazioneId, tenant_id: tenantId }] })
      .mockResolvedValueOnce({ data: [] })
      .mockResolvedValueOnce({ data: [{ id: 'v1' }] });
    vi.mocked(rest.post).mockResolvedValue({ data: [{ id: 'v1' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'POST',
      url: `/v1/segnalazioni/${segnalazioneId}/vote-toggle`,
      payload: { tenant_id: tenantId, user_id: userId }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ vote_active: true, votes_count: 1 });

    await app.close();
  });

  it('creates segnalazione from wizard payload', async () => {
    const rest = mockRest();
    vi.mocked(rest.post)
      .mockResolvedValueOnce({ data: [{ id: 's-id', codice: 'SGN-1', stato: 'in_attesa', titolo: 'Lampione rotto' }] })
      .mockResolvedValueOnce({ data: [{ id: 't1' }] })
      .mockResolvedValueOnce({ data: [{ id: 'snap1' }] })
      .mockResolvedValueOnce({ data: [{ id: 'audit1' }] });

    const app = await buildServer(rest);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/segnalazioni/wizard',
      payload: {
        tenant_id: '1386f06c-8d0c-4a99-a157-d3576447add0',
        titolo: 'Lampione rotto',
        descrizione: 'Il lampione non funziona da tre giorni in via Roma.',
        tags: ['illuminazione']
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({ id: 's-id', titolo: 'Lampione rotto' });

    await app.close();
  });
});
