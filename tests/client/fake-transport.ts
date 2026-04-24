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

export interface FakeTransportOptions {
  url?: string;
  windowOpenerFeatures?: string;
  [key: string]: unknown;
}

export type RequestHandler = (
  request: JsonRpcRequest,
) => JsonRpcResponse | undefined | Promise<JsonRpcResponse | undefined>;

/**
 * In-memory {@link Transport} for tests. Register handlers via
 * {@link onRequest}; each handler sees every request and may return either a
 * response (echoing `request.id`) or `undefined` to pass. Handlers are tried
 * in registration order and the first response wins — so tests can compose
 * independent per-method helpers without overwriting each other.
 */
export class FakeTransport implements Transport {
  static instances: FakeTransport[] = [];

  static last(): FakeTransport {
    const t = FakeTransport.instances.at(-1);
    if (!t) throw new Error('No FakeTransport instance exists');
    return t;
  }

  static reset(): void {
    FakeTransport.instances = [];
  }

  readonly options: FakeTransportOptions;
  readonly requests: JsonRpcRequest[] = [];
  readonly #handlers: RequestHandler[] = [];

  constructor(options: FakeTransportOptions = {}) {
    this.options = options;
    FakeTransport.instances.push(this);
  }

  onRequest(handler: RequestHandler): void {
    this.#handlers.push(handler);
  }

  async establishChannel(): Promise<Channel> {
    return new FakeChannel(this.#handlers, this.requests);
  }
}

class FakeChannel implements Channel {
  closed = false;
  readonly #handlers: RequestHandler[];
  readonly #requests: JsonRpcRequest[];
  readonly #responseListeners = new Set<(response: JsonRpcResponse) => void>();
  readonly #closeListeners = new Set<() => void>();

  constructor(handlers: RequestHandler[], requests: JsonRpcRequest[]) {
    this.#handlers = handlers;
    this.#requests = requests;
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
      throw new Error('FakeTransport: cannot send on a closed channel');
    }
    this.#requests.push(request);
    // Per JSON-RPC 2.0, a request without an id is a Notification and receives
    // no response. Mirroring that means tests whose code forgets to set an id
    // will hang on the signer's correlation wait and fail via test timeout —
    // the same way they would against a real signer.
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
