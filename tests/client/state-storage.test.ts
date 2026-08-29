import { Principal } from '@icp-sdk/core/principal';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  LocalStateStorage,
  MemoryStateStorage,
  type SessionState,
} from '../../src/client/state-storage.ts';

const state = {
  principal: Principal.selfAuthenticating(new Uint8Array([1, 2, 3])),
  expiration: BigInt('1893456000000000000'),
};

/** What a store hands back: what was written, plus the fact it is held here. */
const held: SessionState = { ...state, held: true };

describe('MemoryStateStorage', () => {
  it('holds a state and gives it back', () => {
    const storage = new MemoryStateStorage();
    expect(storage.get()).toBeNull();

    storage.set(state);
    expect(storage.get()).toEqual(held);

    storage.remove();
    expect(storage.get()).toBeNull();
  });

  it('reports a record it has as held, because nothing else can have written it', () => {
    const storage = new MemoryStateStorage();
    storage.set(state);

    expect(storage.get()?.held).toBe(true);
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
    expect(storage.get()).toEqual(held);

    storage.remove();
    expect(storage.get()).toBeNull();
  });

  it('is read by another instance under the same key, which is what makes it an origin-wide answer', () => {
    new LocalStateStorage().set(state);

    expect(new LocalStateStorage().get()).toEqual(held);
  });

  it('discards what it holds, which for a store that publishes nothing is a removal', () => {
    const storage = new LocalStateStorage();
    storage.set(state);

    storage.discard();

    expect(storage.get()).toBeNull();
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

  it('tells a subscriber about a write here and about one in another tab', () => {
    const storage = new LocalStateStorage();
    const listener = vi.fn();
    const unsubscribe = storage.subscribe(listener);

    storage.set(state);
    expect(listener).toHaveBeenCalledTimes(1);

    // `storage` does not fire in the tab that wrote, so this is how another
    // tab's sign-out arrives: the value is already there, and the event says so.
    localStorage.removeItem(storage.key);
    globalThis.dispatchEvent(new StorageEvent('storage', { key: storage.key }));
    expect(listener).toHaveBeenCalledTimes(2);

    // Something else changing is not this changing.
    globalThis.dispatchEvent(new StorageEvent('storage', { key: 'unrelated' }));
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    storage.set(state);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('announces a change only once it can be read', () => {
    const storage = new LocalStateStorage();
    let seen: unknown = 'not read';
    storage.subscribe(() => {
      seen = storage.get();
    });

    storage.set(state);

    expect(seen).toEqual(held);
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
