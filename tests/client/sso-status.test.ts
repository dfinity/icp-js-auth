import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SSO_CHECK_DELAY_MS,
  SSO_POLL_MAX_MS,
  SSO_POLL_MIN_MS,
  SSO_RECHECK_AFTER_MS,
  type SsoDomainService,
  SsoStatusChecker,
} from '../../src/client/sso-status.ts';

type Answer = Awaited<ReturnType<SsoDomainService['app_sso_domain_status']>>;

const PENDING: Answer = { Pending: null };

/** A service whose status answers come from a queue; once it runs dry it keeps giving the last. */
function fakeService(...answers: Answer[]) {
  const queue = [...answers];
  let last: Answer = PENDING;
  const service = {
    app_sso_domain_check: vi.fn(async (_domain: string) => undefined),
    app_sso_domain_status: vi.fn(async (_domain: string) => {
      last = queue.shift() ?? last;
      return last;
    }),
    answer(next: Answer) {
      queue.length = 0;
      last = next;
    },
  };
  return service;
}

/** `null` builds the checker for a value that is not a domain. */
function build(service: ReturnType<typeof fakeService>, domain: string | null = 'dfinity.org') {
  const onChange = vi.fn();
  const checker = new SsoStatusChecker(domain ?? undefined, async () => service, onChange);
  return { checker, onChange };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('SsoStatusChecker', () => {
  it('waits before its first call, then checks once and reads the status', async () => {
    const service = fakeService({ Available: { name: ['DFINITY'] } });
    const { checker } = build(service);

    expect(checker.status).toEqual({ state: 'checking' });
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS - 1);
    expect(service.app_sso_domain_check).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(service.app_sso_domain_check).toHaveBeenCalledExactlyOnceWith('dfinity.org');
    expect(service.app_sso_domain_status).toHaveBeenCalledExactlyOnceWith('dfinity.org');
    expect(checker.status).toEqual({ state: 'available', name: 'DFINITY' });
  });

  it('reports available without a name when the organization publishes none', async () => {
    const { checker } = build(fakeService({ Available: { name: [] } }));
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);
    expect(checker.status).toEqual({ state: 'available' });
  });

  it('reports unavailable with the time Internet Identity will fetch again', async () => {
    const retryAt = Date.UTC(2026, 9, 7, 12, 0, 0);
    const { checker } = build(
      fakeService({ Unavailable: { retry_after: [BigInt(retryAt) * 1_000_000n] } }),
    );
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);
    expect(checker.status).toEqual({ state: 'unavailable', retryAfter: new Date(retryAt) });
  });

  it('reports unavailable without retryAfter when a retry cannot help', async () => {
    const { checker } = build(fakeService({ Unavailable: { retry_after: [] } }));
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);
    expect(checker.status).toEqual({ state: 'unavailable' });
  });

  it('polls the query with a backoff while the answer is pending, and checks only once', async () => {
    const service = fakeService();
    build(service);
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);
    expect(service.app_sso_domain_status).toHaveBeenCalledTimes(1);

    const waits = [SSO_POLL_MIN_MS, SSO_POLL_MIN_MS * 2, SSO_POLL_MAX_MS, SSO_POLL_MAX_MS];
    for (const [index, wait] of waits.entries()) {
      await vi.advanceTimersByTimeAsync(wait - 1);
      expect(service.app_sso_domain_status).toHaveBeenCalledTimes(index + 1);
      await vi.advanceTimersByTimeAsync(1);
      expect(service.app_sso_domain_status).toHaveBeenCalledTimes(index + 2);
    }
    expect(service.app_sso_domain_check).toHaveBeenCalledTimes(1);
  });

  it('stops polling on a final answer', async () => {
    const service = fakeService(PENDING, PENDING, { Available: { name: [] } });
    const { checker } = build(service);
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS + SSO_POLL_MIN_MS * 3);
    expect(checker.status).toEqual({ state: 'available' });

    const reads = service.app_sso_domain_status.mock.calls.length;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(service.app_sso_domain_status).toHaveBeenCalledTimes(reads);
  });

  it('checks again once the answer has been pending for the abandon window', async () => {
    const service = fakeService();
    build(service);
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS + SSO_RECHECK_AFTER_MS - 1);
    expect(service.app_sso_domain_check).toHaveBeenCalledTimes(1);

    // The first read past the window, then one more interval.
    await vi.advanceTimersByTimeAsync(SSO_POLL_MAX_MS * 2);
    expect(service.app_sso_domain_check).toHaveBeenCalledTimes(2);
  });

  it('retries a status read that failed, at the next interval', async () => {
    const service = fakeService();
    service.app_sso_domain_status.mockRejectedValueOnce(new Error('offline'));
    const { checker } = build(service);
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);
    expect(checker.status).toEqual({ state: 'checking' });

    service.answer({ Available: { name: [] } });
    await vi.advanceTimersByTimeAsync(SSO_POLL_MIN_MS);
    expect(checker.status).toEqual({ state: 'available' });
  });

  it('still reads the status when the check update fails', async () => {
    const service = fakeService({ Available: { name: [] } });
    service.app_sso_domain_check.mockRejectedValueOnce(new Error('rejected'));
    const { checker } = build(service);
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);
    expect(checker.status).toEqual({ state: 'available' });
  });

  it('builds the service again when building it failed', async () => {
    const service = fakeService({ Available: { name: [] } });
    const create = vi
      .fn<() => Promise<SsoDomainService>>()
      .mockRejectedValueOnce(new Error('no agent'))
      .mockResolvedValue(service);
    const checker = new SsoStatusChecker('dfinity.org', create, vi.fn());
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS + SSO_POLL_MIN_MS);
    expect(checker.status).toEqual({ state: 'available' });
    expect(create).toHaveBeenCalledTimes(2);
  });

  it('keeps the same object until the answer changes', async () => {
    const service = fakeService();
    const { checker, onChange } = build(service);
    const checking = checker.status;
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS + SSO_POLL_MIN_MS * 3);
    expect(checker.status).toBe(checking);
    expect(onChange).not.toHaveBeenCalled();

    service.answer({ Available: { name: ['DFINITY'] } });
    await vi.advanceTimersByTimeAsync(SSO_POLL_MAX_MS);
    const available = checker.status;
    expect(available).toEqual({ state: 'available', name: 'DFINITY' });
    expect(checker.status).toBe(available);
    expect(onChange).toHaveBeenCalledOnce();
  });

  it('treats a value that is not a domain as invalid and never calls', async () => {
    const service = fakeService();
    const { checker, onChange } = build(service, null);
    expect(checker.status).toEqual({ state: 'invalid' });

    checker.refresh();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(service.app_sso_domain_check).not.toHaveBeenCalled();
    expect(service.app_sso_domain_status).not.toHaveBeenCalled();
    expect(checker.status).toEqual({ state: 'invalid' });
    expect(onChange).not.toHaveBeenCalled();
  });

  it('checks again on refresh, through checking', async () => {
    const service = fakeService({ Unavailable: { retry_after: [] } });
    const { checker, onChange } = build(service);
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);
    expect(checker.status).toEqual({ state: 'unavailable' });

    service.answer({ Available: { name: [] } });
    checker.refresh();
    expect(checker.status).toEqual({ state: 'checking' });
    await vi.advanceTimersByTimeAsync(0);
    expect(service.app_sso_domain_check).toHaveBeenCalledTimes(2);
    expect(checker.status).toEqual({ state: 'available' });
    expect(onChange).toHaveBeenCalledTimes(3);
  });

  it('does not check again on its own once retryAfter passes', async () => {
    const retryAt = Date.now() + 60_000;
    const service = fakeService({
      Unavailable: { retry_after: [BigInt(retryAt) * 1_000_000n] },
    });
    build(service);
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(service.app_sso_domain_check).toHaveBeenCalledTimes(1);
    expect(service.app_sso_domain_status).toHaveBeenCalledTimes(1);
  });

  it('never calls when disposed before its first call', async () => {
    const service = fakeService();
    const { checker } = build(service);
    checker.dispose();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(service.app_sso_domain_check).not.toHaveBeenCalled();
  });

  it('stops polling when disposed, and drops an answer already in flight', async () => {
    let release: (answer: Answer) => void = () => undefined;
    const service = fakeService();
    service.app_sso_domain_status.mockImplementationOnce(
      () =>
        new Promise<Answer>((resolve) => {
          release = resolve;
        }),
    );
    const { checker, onChange } = build(service);
    await vi.advanceTimersByTimeAsync(SSO_CHECK_DELAY_MS);

    checker.dispose();
    release({ Available: { name: [] } });
    await vi.advanceTimersByTimeAsync(60_000);
    expect(checker.status).toEqual({ state: 'checking' });
    expect(onChange).not.toHaveBeenCalled();
    expect(service.app_sso_domain_status).toHaveBeenCalledTimes(1);
  });

  it('ignores refresh once disposed', async () => {
    const service = fakeService();
    const { checker } = build(service);
    checker.dispose();
    checker.refresh();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(service.app_sso_domain_check).not.toHaveBeenCalled();
  });
});
