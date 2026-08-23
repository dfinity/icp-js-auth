import { beforeEach, describe, expect, it } from 'vitest';
import { LocalIdentityStorage } from '../../src/client/local-identity-storage.ts';

describe('LocalIdentityStorage', () => {
  beforeEach(() => localStorage.clear());

  it('create() mints an identity without persisting it', async () => {
    const storage = new LocalIdentityStorage();

    await storage.create();

    expect(await storage.get()).toBeNull();
  });

  it('persists and restores the same Ed25519 identity via set()', async () => {
    const storage = new LocalIdentityStorage();

    const created = await storage.create();
    await storage.set(created);
    const restored = await storage.get();

    expect(restored?.getPrincipal().toText()).toBe(created.getPrincipal().toText());
  });

  it('returns null when nothing is stored', async () => {
    expect(await new LocalIdentityStorage().get()).toBeNull();
  });

  it('removes the stored identity', async () => {
    const storage = new LocalIdentityStorage();
    await storage.set(await storage.create());

    await storage.remove();

    expect(await storage.get()).toBeNull();
  });
});
