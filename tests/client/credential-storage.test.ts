import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { beforeEach, describe, expect, it } from 'vitest';
import { LocalCredentialStorage } from '../../src/client/local-credential-storage.ts';
import { MemoryCredentialStorage } from '../../src/client/memory-credential-storage.ts';
import { slotsFor } from '../../src/client/slots.ts';

/** The bare names, which is what a client with no namespace writes under. */
const SLOTS = slotsFor();

const testChain = async () => {
  const key = Ed25519KeyIdentity.generate();
  return DelegationChain.create(key, key.getPublicKey(), new Date(Date.now() + 3.6e6));
};

describe('MemoryCredentialStorage', () => {
  it('reports what it is: seen by no other tab, and gone on a reload', () => {
    const storage = new MemoryCredentialStorage();

    expect(storage.shared).toBe(false);
    expect(storage.durable).toBe(false);
  });

  it('hands back the record it was given rather than a copy', async () => {
    const storage = new MemoryCredentialStorage();
    const identity = await storage.create();
    const chain = await testChain();

    await storage.set(SLOTS.session, { identity, chain });

    const stored = await storage.get(SLOTS.session);
    expect(stored?.identity).toBe(identity);
    expect(stored?.chain).toBe(chain);
  });

  it('keeps slots apart, and removes one at a time', async () => {
    const storage = new MemoryCredentialStorage();
    const session = await storage.create();
    const pending = await storage.create();
    await storage.set(SLOTS.session, { identity: session, chain: await testChain() });
    await storage.set(SLOTS.sessionPending, { identity: pending });

    await storage.remove(SLOTS.sessionPending);

    expect(await storage.get(SLOTS.session)).not.toBeNull();
    expect(await storage.get(SLOTS.sessionPending)).toBeNull();
  });

  it('shares nothing between instances, which is what makes a tab alone', async () => {
    const one = new MemoryCredentialStorage();
    await one.set(SLOTS.session, { identity: await one.create(), chain: await testChain() });

    expect(await new MemoryCredentialStorage().get(SLOTS.session)).toBeNull();
  });

  it('generates a key whose private half cannot be read back', async () => {
    const identity = await new MemoryCredentialStorage().create();

    expect(identity.getKeyPair().privateKey.extractable).toBe(false);
  });
});

describe('LocalCredentialStorage', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('reports what it is: shared between tabs, and durable', () => {
    const storage = new LocalCredentialStorage();

    expect(storage.shared).toBe(true);
    expect(storage.durable).toBe(true);
  });

  it('round-trips a key and its delegation through strings', async () => {
    const storage = new LocalCredentialStorage();
    const identity = await storage.create();
    const chain = await testChain();

    await storage.set(SLOTS.session, { identity, chain });

    const stored = await storage.get(SLOTS.session);
    expect(stored?.identity.toJSON()).toEqual(identity.toJSON());
    expect(stored?.chain?.toJSON()).toEqual(chain.toJSON());
  });

  it('generates a key it can serialise, which is why it is not the same type', async () => {
    const identity = await new LocalCredentialStorage().create();

    expect(identity).toBeInstanceOf(Ed25519KeyIdentity);
  });

  it('is read by another instance under the same prefix', async () => {
    const identity = await new LocalCredentialStorage().create();
    await new LocalCredentialStorage().set(SLOTS.session, { identity });

    expect(await new LocalCredentialStorage().get(SLOTS.session)).not.toBeNull();
  });

  it('keeps clients under different prefixes apart', async () => {
    const one = new LocalCredentialStorage('one-');
    await one.set(SLOTS.session, { identity: await one.create() });

    expect(await new LocalCredentialStorage('two-').get(SLOTS.session)).toBeNull();
  });

  it('reports nothing stored rather than throwing on a record it cannot read', async () => {
    const storage = new LocalCredentialStorage();
    localStorage.setItem(`ic-${SLOTS.session}`, 'not a credential');

    expect(await storage.get(SLOTS.session)).toBeNull();
  });
});
