import { describe, expect, it } from 'vitest';
import { slotsFor } from '../../src/client/slots.ts';

describe('slotsFor', () => {
  it('names everything a client writes under, the state record included', () => {
    expect(slotsFor()).toEqual({
      session: 'session',
      app: 'app',
      sessionPending: 'session-pending',
      appPending: 'app-pending',
      state: 'ic-session-state',
    });
  });

  it('moves every slot at once, so none can be renamed while another is missed', () => {
    const slots = slotsFor('second');

    expect(slots).toEqual({
      session: 'second:session',
      app: 'second:app',
      sessionPending: 'second:session-pending',
      appPending: 'second:app-pending',
      state: 'second:ic-session-state',
    });
    expect(Object.values(slots)).toEqual(Object.values(slotsFor()).map((slot) => `second:${slot}`));
  });
});
