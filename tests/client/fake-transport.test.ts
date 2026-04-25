import { afterEach, describe, expect, it, vi } from 'vitest';
import { FakeTransport } from './fake-transport.ts';

afterEach(() => {
  FakeTransport.reset();
});

describe('FakeTransport', () => {
  describe('instance tracking', () => {
    it('should record instances in construction order', () => {
      const a = new FakeTransport({ url: 'a' });
      const b = new FakeTransport({ url: 'b' });
      expect(FakeTransport.instances).toEqual([a, b]);
      expect(FakeTransport.last()).toBe(b);
    });

    it('should throw from last() when no instance exists', () => {
      expect(() => FakeTransport.last()).toThrow('No FakeTransport instance exists');
    });

    it('should clear instances on reset', () => {
      new FakeTransport();
      FakeTransport.reset();
      expect(FakeTransport.instances).toEqual([]);
    });

    it('should capture constructor options', () => {
      const t = new FakeTransport({ url: 'https://example.com', windowOpenerFeatures: 'w=1' });
      expect(t.options).toEqual({ url: 'https://example.com', windowOpenerFeatures: 'w=1' });
    });
  });

  describe('send', () => {
    it('should record every request', async () => {
      const t = new FakeTransport();
      const channel = await t.establishChannel();
      await channel.send({ jsonrpc: '2.0', id: '1', method: 'foo' });
      await channel.send({ jsonrpc: '2.0', id: '2', method: 'bar' });
      expect(t.requests.map((r) => r.method)).toEqual(['foo', 'bar']);
    });

    it('should not dispatch when id is undefined (notification)', async () => {
      const t = new FakeTransport();
      const handler = vi.fn();
      t.onRequest(handler);
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('response', listener);

      await channel.send({ jsonrpc: '2.0', method: 'foo' });

      expect(handler).not.toHaveBeenCalled();
      expect(listener).not.toHaveBeenCalled();
    });

    it('should not dispatch when id is null', async () => {
      const t = new FakeTransport();
      const handler = vi.fn();
      t.onRequest(handler);
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('response', listener);

      await channel.send({ jsonrpc: '2.0', id: null, method: 'foo' });

      expect(handler).not.toHaveBeenCalled();
      expect(listener).not.toHaveBeenCalled();
    });

    it('should invoke the handler and dispatch its response for an id-ful request', async () => {
      const t = new FakeTransport();
      t.onRequest((req) => ({
        jsonrpc: '2.0',
        id: req.id!,
        result: `for-${req.method}`,
      }));
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('response', listener);

      await channel.send({ jsonrpc: '2.0', id: 'abc', method: 'foo' });

      expect(listener).toHaveBeenCalledWith({ jsonrpc: '2.0', id: 'abc', result: 'for-foo' });
    });

    it('should not dispatch when no handler is registered', async () => {
      const t = new FakeTransport();
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('response', listener);

      await channel.send({ jsonrpc: '2.0', id: '1', method: 'foo' });

      expect(listener).not.toHaveBeenCalled();
    });

    it('should try handlers in order and stop at the first non-undefined response', async () => {
      const t = new FakeTransport();
      const a = vi.fn((req) =>
        req.method === 'a' ? { jsonrpc: '2.0' as const, id: req.id!, result: 'a' } : undefined,
      );
      const b = vi.fn((req) =>
        req.method === 'b' ? { jsonrpc: '2.0' as const, id: req.id!, result: 'b' } : undefined,
      );
      const c = vi.fn(() => ({ jsonrpc: '2.0' as const, id: null, result: 'c' }));
      t.onRequest(a);
      t.onRequest(b);
      t.onRequest(c);
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('response', listener);

      await channel.send({ jsonrpc: '2.0', id: '1', method: 'a' });
      expect(listener).toHaveBeenLastCalledWith(expect.objectContaining({ result: 'a' }));
      expect(b).not.toHaveBeenCalled();
      expect(c).not.toHaveBeenCalled();

      await channel.send({ jsonrpc: '2.0', id: '2', method: 'b' });
      expect(listener).toHaveBeenLastCalledWith(expect.objectContaining({ result: 'b' }));
      expect(c).not.toHaveBeenCalled();
    });

    it('should not dispatch when every handler returns undefined', async () => {
      const t = new FakeTransport();
      t.onRequest(() => undefined);
      t.onRequest(() => undefined);
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('response', listener);

      await channel.send({ jsonrpc: '2.0', id: '1', method: 'foo' });

      expect(listener).not.toHaveBeenCalled();
    });

    it('should await async handlers before dispatching', async () => {
      const t = new FakeTransport();
      t.onRequest(async (req) => {
        await Promise.resolve();
        return { jsonrpc: '2.0', id: req.id!, result: 'async' };
      });
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('response', listener);

      await channel.send({ jsonrpc: '2.0', id: '1', method: 'foo' });

      expect(listener).toHaveBeenCalledWith({ jsonrpc: '2.0', id: '1', result: 'async' });
    });

    it('should reject send on a closed channel', async () => {
      const t = new FakeTransport();
      const channel = await t.establishChannel();
      await channel.close();

      await expect(channel.send({ jsonrpc: '2.0', id: '1', method: 'foo' })).rejects.toThrow(
        'closed',
      );
    });
  });

  describe('addEventListener', () => {
    it('should return an unsubscribe for response listeners', async () => {
      const t = new FakeTransport();
      t.onRequest((req) => ({ jsonrpc: '2.0', id: req.id!, result: 'ok' }));
      const channel = await t.establishChannel();
      const listener = vi.fn();
      const unsubscribe = channel.addEventListener('response', listener);
      unsubscribe();

      await channel.send({ jsonrpc: '2.0', id: '1', method: 'foo' });

      expect(listener).not.toHaveBeenCalled();
    });

    it('should return an unsubscribe for close listeners', async () => {
      const t = new FakeTransport();
      const channel = await t.establishChannel();
      const listener = vi.fn();
      const unsubscribe = channel.addEventListener('close', listener);
      unsubscribe();

      await channel.close();

      expect(listener).not.toHaveBeenCalled();
    });
  });

  describe('close', () => {
    it('should mark the channel closed and notify listeners', async () => {
      const t = new FakeTransport();
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('close', listener);

      await channel.close();

      expect(channel.closed).toBe(true);
      expect(listener).toHaveBeenCalledTimes(1);
    });

    it('should be idempotent', async () => {
      const t = new FakeTransport();
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('close', listener);

      await channel.close();
      await channel.close();

      expect(listener).toHaveBeenCalledTimes(1);
    });
  });

  describe('handler registration', () => {
    it('should pick up handlers registered after establishChannel', async () => {
      const t = new FakeTransport();
      const channel = await t.establishChannel();
      const listener = vi.fn();
      channel.addEventListener('response', listener);

      t.onRequest((req) => ({ jsonrpc: '2.0', id: req.id!, result: 'late' }));
      await channel.send({ jsonrpc: '2.0', id: '1', method: 'foo' });

      expect(listener).toHaveBeenCalledWith(expect.objectContaining({ result: 'late' }));
    });

    it('should share handlers across concurrent channels', async () => {
      const t = new FakeTransport();
      t.onRequest((req) => ({ jsonrpc: '2.0', id: req.id!, result: 'shared' }));
      const [ch1, ch2] = await Promise.all([t.establishChannel(), t.establishChannel()]);
      const l1 = vi.fn();
      const l2 = vi.fn();
      ch1.addEventListener('response', l1);
      ch2.addEventListener('response', l2);

      await Promise.all([
        ch1.send({ jsonrpc: '2.0', id: 'a', method: 'foo' }),
        ch2.send({ jsonrpc: '2.0', id: 'b', method: 'foo' }),
      ]);

      expect(l1).toHaveBeenCalledWith(expect.objectContaining({ id: 'a', result: 'shared' }));
      expect(l2).toHaveBeenCalledWith(expect.objectContaining({ id: 'b', result: 'shared' }));
    });
  });
});
