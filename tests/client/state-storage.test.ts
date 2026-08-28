import { Principal } from '@icp-sdk/core/principal';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  LocalStateStorage,
  MemoryStateStorage,
  type SessionState,
} from '../../src/client/state-storage.ts';

const state: SessionState = {
  principal: Principal.selfAuthenticating(new Uint8Array([1, 2, 3])),
  expiration: BigInt('1893456000000000000'),
};

describe('MemoryStateStorage', () => {
  it('holds a state and gives it back', () => {
    const storage = new MemoryStateStorage();
    expect(storage.get()).toBeNull();

    storage.set(state);
    expect(storage.get()).toEqual(state);

    storage.remove();
    expect(storage.get()).toBeNull();
  });

  it('shares nothing between instances', () => {
    const one = new MemoryStateStorage();
    one.set(state);

    expect(new MemoryStateStorage().get()).toBeNull();
  });
});

describe('LocalStateStorage', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('holds a state and gives it back', () => {
    const storage = new LocalStateStorage();
    expect(storage.get()).toBeNull();

    storage.set(state);
    expect(storage.get()).toEqual(state);

    storage.remove();
    expect(storage.get()).toBeNull();
  });

  it('is read by another instance under the same key, which is what makes it an origin-wide answer', () => {
    new LocalStateStorage().set(state);

    expect(new LocalStateStorage().get()).toEqual(state);
  });

  it('keeps clients under different keys apart', () => {
    new LocalStateStorage('one').set(state);

    expect(new LocalStateStorage('two').get()).toBeNull();
  });

  it('carries the expiration as a bigint, which JSON could not', () => {
    const storage = new LocalStateStorage();
    storage.set(state);

    expect(storage.get()?.expiration).toBe(state.expiration);
  });

  it.each([
    ['no separator', 'not-a-state'],
    ['an unparseable principal', 'not-a-principal|123'],
    ['an unparseable expiration', `${state.principal.toText()}|not-a-number`],
  ])('reports nothing stored rather than throwing on %s', (_name, raw) => {
    const storage = new LocalStateStorage();
    localStorage.setItem(storage.key, raw);

    expect(storage.get()).toBeNull();
  });
});
