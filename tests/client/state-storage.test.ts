import { Principal } from '@icp-sdk/core/principal';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { slotsFor } from '../../src/client/slots.ts';
import {
  LocalStateStorage,
  MemoryStateStorage,
  type SessionState,
} from '../../src/client/state-storage.ts';

const STATE_KEY = slotsFor().state;

const state = {
  principal: Principal.selfAuthenticating(new Uint8Array([1, 2, 3])),
  expiration: BigInt('1893456000000000000'),
};

/** What a store hands back: what was written, plus the fact it is held here. */
const held: SessionState = { ...state, held: true };

describe('MemoryStateStorage', () => {
  it('holds a state and gives it back', () => {
    const storage = new MemoryStateStorage();
    expect(storage.get(STATE_KEY)).toBeNull();

    storage.set(STATE_KEY, state);
    expect(storage.get(STATE_KEY)).toEqual(held);

    storage.remove(STATE_KEY);
    expect(storage.get(STATE_KEY)).toBeNull();
  });

  it('reports a record it has as held, because nothing else can have written it', () => {
    const storage = new MemoryStateStorage();
    storage.set(STATE_KEY, state);

    expect(storage.get(STATE_KEY)?.held).toBe(true);
  });

  it('shares nothing between instances', () => {
    const one = new MemoryStateStorage();
    one.set(STATE_KEY, state);

    expect(new MemoryStateStorage().get(STATE_KEY)).toBeNull();
  });

  it('keeps clients under different keys apart', () => {
    const storage = new MemoryStateStorage();
    storage.set('one', state);

    expect(storage.get('two')).toBeNull();
  });

  it('discards what it holds, which for a store that publishes nothing is a removal', () => {
    const storage = new MemoryStateStorage();
    storage.set(STATE_KEY, state);

    storage.discard(STATE_KEY);

    expect(storage.get(STATE_KEY)).toBeNull();
  });

  // Two clients on one page can be handed the same instance, so the one that did
  // not write has to be told. Without this it goes on answering for a sign-in
  // that has been replaced under it.
  it('tells a subscriber about a write, and stops when unsubscribed', () => {
    const storage = new MemoryStateStorage();
    const listener = vi.fn();
    const unsubscribe = storage.subscribe(STATE_KEY, listener);

    storage.set(STATE_KEY, state);
    expect(listener).toHaveBeenCalledTimes(1);

    storage.remove(STATE_KEY);
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    storage.set(STATE_KEY, state);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('tells a subscriber nothing about a key it did not subscribe to', () => {
    const storage = new MemoryStateStorage();
    const listener = vi.fn();
    storage.subscribe('one', listener);

    storage.set('two', state);

    expect(listener).not.toHaveBeenCalled();
  });

  it('says nothing when a write leaves the record as it was', () => {
    const storage = new MemoryStateStorage();
    storage.set(STATE_KEY, state);
    const listener = vi.fn();
    storage.subscribe(STATE_KEY, listener);

    storage.set(STATE_KEY, { ...state });

    expect(listener).not.toHaveBeenCalled();
  });

  it('announces a change only once it can be read', () => {
    const storage = new MemoryStateStorage();
    let seen: unknown = 'not read';
    storage.subscribe(STATE_KEY, () => {
      seen = storage.get(STATE_KEY);
    });

    storage.set(STATE_KEY, state);

    expect(seen).toEqual(held);
  });
});

describe('LocalStateStorage', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('holds a state and gives it back', () => {
    const storage = new LocalStateStorage();
    expect(storage.get(STATE_KEY)).toBeNull();

    storage.set(STATE_KEY, state);
    expect(storage.get(STATE_KEY)).toEqual(held);

    storage.remove(STATE_KEY);
    expect(storage.get(STATE_KEY)).toBeNull();
  });

  it('is read by another instance under the same key, which is what makes it an origin-wide answer', () => {
    new LocalStateStorage().set(STATE_KEY, state);

    expect(new LocalStateStorage().get(STATE_KEY)).toEqual(held);
  });

  it('discards what it holds, which for a store that publishes nothing is a removal', () => {
    const storage = new LocalStateStorage();
    storage.set(STATE_KEY, state);

    storage.discard(STATE_KEY);

    expect(storage.get(STATE_KEY)).toBeNull();
  });

  it('keeps clients under different keys apart', () => {
    const storage = new LocalStateStorage();
    storage.set('one', state);

    expect(storage.get('two')).toBeNull();
  });

  it('carries the expiration as a bigint, which JSON could not', () => {
    const storage = new LocalStateStorage();
    storage.set(STATE_KEY, state);

    expect(storage.get(STATE_KEY)?.expiration).toBe(state.expiration);
  });

  it('tells a subscriber about a write here and about one in another tab', () => {
    const storage = new LocalStateStorage();
    const listener = vi.fn();
    const unsubscribe = storage.subscribe(STATE_KEY, listener);

    storage.set(STATE_KEY, state);
    expect(listener).toHaveBeenCalledTimes(1);

    // `storage` does not fire in the tab that wrote, so this is how another
    // tab's sign-out arrives: the value is already there, and the event says so.
    localStorage.removeItem(STATE_KEY);
    globalThis.dispatchEvent(new StorageEvent('storage', { key: STATE_KEY }));
    expect(listener).toHaveBeenCalledTimes(2);

    // Something else changing is not this changing.
    globalThis.dispatchEvent(new StorageEvent('storage', { key: 'unrelated' }));
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    storage.set(STATE_KEY, state);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('tells a subscriber nothing about a key it did not subscribe to', () => {
    const storage = new LocalStateStorage();
    const listener = vi.fn();
    storage.subscribe('one', listener);

    storage.set('two', state);

    expect(listener).not.toHaveBeenCalled();
  });

  it('announces a change only once it can be read', () => {
    const storage = new LocalStateStorage();
    let seen: unknown = 'not read';
    storage.subscribe(STATE_KEY, () => {
      seen = storage.get(STATE_KEY);
    });

    storage.set(STATE_KEY, state);

    expect(seen).toEqual(held);
  });

  it.each([
    ['no separator', 'not-a-state'],
    ['an unparseable principal', 'not-a-principal|123'],
    ['an unparseable expiration', `${state.principal.toText()}|not-a-number`],
  ])('reports nothing stored rather than throwing on %s', (_name, raw) => {
    const storage = new LocalStateStorage();
    localStorage.setItem(STATE_KEY, raw);

    expect(storage.get(STATE_KEY)).toBeNull();
  });
});
