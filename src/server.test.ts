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
    const response = await app.inject({
      method: 'POST',
      url: '/v1/tenants',
      payload: { name: 'Comune Nuovo' }
    });

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
});
