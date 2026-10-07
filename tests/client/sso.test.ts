import { describe, expect, it } from 'vitest';
import { normalizeSsoDomain } from '../../src/client/sso.ts';

describe('normalizeSsoDomain', () => {
  it.each([
    ['a domain', 'dfinity.org', 'dfinity.org'],
    ['a domain with whitespace and capitals', '  DFINITY.org  ', 'dfinity.org'],
    ['an internationalized domain', 'zürich.example', 'xn--zrich-kva.example'],
    ['a loopback host with a port', 'localhost:11107', 'localhost:11107'],
    ['a loopback address', '127.0.0.1', '127.0.0.1'],
    ['a domain with a hyphen and digits', 'sso-2.dfinity.org', 'sso-2.dfinity.org'],
  ])('accepts %s', (_case, domain, expected) => {
    expect(normalizeSsoDomain(domain)).toBe(expected);
  });

  it.each([
    ['an empty domain', ''],
    ['a bare hostname', 'dfinity'],
    ['a domain carrying a scheme', 'https://dfinity.org'],
    ['a domain carrying a path', 'dfinity.org/sso'],
    ['a domain carrying a query', 'dfinity.org?x=1'],
    ['a domain carrying a fragment', 'dfinity.org#x'],
    ['a domain carrying userinfo', 'user:pw@dfinity.org'],
    ['a domain carrying a port', 'sso.dfinity.org:8443'],
    ['a domain carrying the default port', 'dfinity.org:443'],
    ['a domain carrying an empty port', 'dfinity.org:'],
    ['a domain starting with a dot', '.org'],
    ['a domain with an empty label', 'dfinity..org'],
    ['a label starting with a hyphen', '-dfinity.org'],
    ['a label ending with a hyphen', 'dfinity-.org'],
    ['a label with an underscore', 'df_inity.org'],
    ['a label over 63 characters', `${'a'.repeat(64)}.org`],
    ['a domain carrying a space', 'dfinity .org'],
    ['an authority over 255 characters', `${'a'.repeat(252)}.org`],
  ])('rejects %s', (_case, domain) => {
    expect(() => normalizeSsoDomain(domain)).toThrow();
  });
});
