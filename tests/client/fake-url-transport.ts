import type { Channel, Transport } from '@icp-sdk/signer';

// `JsonRpcRequest` / `JsonRpcResponse` aren't re-exported from the package
// root; extract the request shape from `Channel['send']` and redeclare the
// JSON-RPC 2.0 response shape locally.
type JsonRpcRequest = Parameters<Channel['send']>[0];

interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

type JsonRpcResponse =
  | { jsonrpc: '2.0'; id: string | number | null; result: unknown }
  | { jsonrpc: '2.0'; id: string | number | null; error: JsonRpcError };

export type RequestHandler = (
  request: JsonRpcRequest,
) => JsonRpcResponse | undefined | Promise<JsonRpcResponse | undefined>;

/**
 * In-memory stand-in for `UrlTransport` that lets tests exercise
 * `AuthClient`'s redirect paths without a real page navigation.
 *
 * The real transport persists a call-order journal so a flow replays across
 * the top-level redirect. This fake models the two moving parts `AuthClient`
 * depends on:
 *
 * - `memoize` records each produced value by call order in a **static** journal
 *   shared across instances, so a value captured on one "load" (transport
 *   instance) replays on the next — exactly the cross-redirect guarantee the
 *   real transport gives.
 * - Each instance can either answer requests (`respond = true`, a signer
 *   return) or record them and never respond (`respond = false`, the load that
 *   navigates away), so a test can simulate the first load that redirects and
 *   the return load that completes.
 *
 * Reset all static state with {@link reset} in `beforeEach`; set
 * {@link nextRespond} before constructing the `AuthClient` for a load.
 */
export class FakeUrlTransport implements Transport {
  static instances: FakeUrlTransport[] = [];
  static journal: unknown[] = [];
  static nextRespond = true;

  static reset(): void {
    FakeUrlTransport.instances = [];
    FakeUrlTransport.journal = [];
    FakeUrlTransport.nextRespond = true;
  }

  static last(): FakeUrlTransport {
    const t = FakeUrlTransport.instances.at(-1);
    if (!t) throw new Error('No FakeUrlTransport instance exists');
    return t;
  }

  readonly options: Record<string, unknown>;
  readonly requests: JsonRpcRequest[] = [];
  readonly #handlers: RequestHandler[] = [];
  readonly #respond: boolean;
  #cursor = 0;

  constructor(options: Record<string, unknown> = {}) {
    this.options = options;
    this.#respond = FakeUrlTransport.nextRespond;
    FakeUrlTransport.instances.push(this);
  }

  onRequest(handler: RequestHandler): void {
    this.#handlers.push(handler);
  }

  // Mirrors the real transport's polymorphic memoize: a sync producer returns
  // synchronously (so a value can be read where `await` isn't possible, e.g. in
  // a constructor), an async one returns a promise.
  memoize<T>(produce: () => Promise<T>): Promise<T>;
  memoize<T>(produce: () => T): T;
  memoize<T>(produce: () => T | Promise<T>): T | Promise<T> {
    const index = this.#cursor++;
    if (index < FakeUrlTransport.journal.length) {
      return FakeUrlTransport.journal[index] as T; // replay from an earlier load
    }
    const produced = produce();
    if (produced instanceof Promise) {
      return produced.then((value) => {
        FakeUrlTransport.journal[index] = value;
        return value;
      });
    }
    FakeUrlTransport.journal[index] = produced;
    return produced;
  }

  async establishChannel(): Promise<Channel> {
    return new FakeUrlChannel(this.#handlers, this.requests, this.#respond);
  }
}

class FakeUrlChannel implements Channel {
  closed = false;
  readonly #handlers: RequestHandler[];
  readonly #requests: JsonRpcRequest[];
  readonly #respond: boolean;
  readonly #responseListeners = new Set<(response: JsonRpcResponse) => void>();
  readonly #closeListeners = new Set<() => void>();

  constructor(handlers: RequestHandler[], requests: JsonRpcRequest[], respond: boolean) {
    this.#handlers = handlers;
    this.#requests = requests;
    this.#respond = respond;
  }

  addEventListener(event: 'close', listener: () => void): () => void;
  addEventListener(event: 'response', listener: (response: JsonRpcResponse) => void): () => void;
  addEventListener(
    event: 'close' | 'response',
    listener: ((response: JsonRpcResponse) => void) | (() => void),
  ): () => void {
    if (event === 'response') {
      const fn = listener as (response: JsonRpcResponse) => void;
      this.#responseListeners.add(fn);
      return () => this.#responseListeners.delete(fn);
    }
    const fn = listener as () => void;
    this.#closeListeners.add(fn);
    return () => this.#closeListeners.delete(fn);
  }

  async send(request: JsonRpcRequest): Promise<void> {
    if (this.closed) {
      throw new Error('FakeUrlTransport: cannot send on a closed channel');
    }
    this.#requests.push(request);
    // A load that navigates to the signer records the request but never
    // receives a response in-context (the page unloads), so the request
    // promise stays pending — exactly like the real redirect.
    if (!this.#respond) return;
    if (request.id === undefined || request.id === null) return;
    for (const handler of this.#handlers) {
      const response = await handler(request);
      if (response === undefined) continue;
      for (const listener of this.#responseListeners) listener(response);
      return;
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    for (const listener of this.#closeListeners) listener();
  }
}
