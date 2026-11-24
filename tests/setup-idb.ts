import 'fake-indexeddb/auto';
import { beforeEach } from 'vitest';

const STATE_DB = 'auth-client-state-db';
const NOTIFICATIONS_DB = 'auth-client-notifications';
const STORE = 'ic-keyval';

const request = <T>(req: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

const clear = async (name: string, names: (string | undefined)[]): Promise<void> => {
  if (!names.includes(name)) return;
  const db = await request(indexedDB.open(name));
  try {
    if (db.objectStoreNames.contains(STORE)) {
      await request(db.transaction(STORE, 'readwrite').objectStore(STORE).clear());
    }
  } finally {
    db.close();
  }
};

// The default state store keeps the sign-in in IndexedDB, and a subscribe keeps
// the VAPID key there too, each as long as the test file does. Tests clear
// `localStorage` between them, so these go too. Native IndexedDB rather than
// `IdbKeyVal`, so files that mock `idb` see only their own connections.
beforeEach(async () => {
  const names = (await indexedDB.databases()).map((db) => db.name);
  await clear(STATE_DB, names);
  await clear(NOTIFICATIONS_DB, names);
});
