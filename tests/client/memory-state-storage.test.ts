import { Principal } from '@icp-sdk/core/principal';
import { describe, expect, it, vi } from 'vitest';
import { MemoryStateStorage } from '../../src/client/memory-state-storage.ts';
import { slotsFor } from '../../src/client/slots.ts';
import type { SessionState } from '../../src/client/state-storage.ts';

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
