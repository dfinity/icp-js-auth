import 'fake-indexeddb/auto';
import { beforeEach } from 'vitest';

const STATE_DB = 'auth-client-state-db';
const STATE_STORE = 'ic-keyval';

const request = <T>(req: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

// The default state store keeps the sign-in in IndexedDB, which lives as long as
// the test file does. Tests clear `localStorage` between them, so this goes too.
// Native IndexedDB rather than `IdbKeyVal`, so files that mock `idb` see only
// their own connections.
beforeEach(async () => {
  const names = (await indexedDB.databases()).map((db) => db.name);
  if (!names.includes(STATE_DB)) return;
  const db = await request(indexedDB.open(STATE_DB));
  try {
    if (db.objectStoreNames.contains(STATE_STORE)) {
      await request(db.transaction(STATE_STORE, 'readwrite').objectStore(STATE_STORE).clear());
    }
  } finally {
    db.close();
  }
});
