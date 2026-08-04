import { type IDBPDatabase, openDB } from 'idb';
import { DB_VERSION, KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY } from './storage.js';

type Database = IDBPDatabase<unknown>;
type IDBValidKey = string | number | Date | BufferSource | IDBValidKey[];
const AUTH_DB_NAME = 'auth-client-db';
const OBJECT_STORE_NAME = 'ic-keyval';

const _openDbStore = async (
  dbName = AUTH_DB_NAME,
  storeName = OBJECT_STORE_NAME,
  version: number,
  onTerminated?: () => void,
) => {
  // Clear legacy stored delegations
  if (globalThis.localStorage?.getItem(KEY_STORAGE_DELEGATION)) {
    globalThis.localStorage.removeItem(KEY_STORAGE_DELEGATION);
    globalThis.localStorage.removeItem(KEY_STORAGE_KEY);
  }
  return await openDB(dbName, version, {
    upgrade: (database) => {
      if (database.objectStoreNames.contains(storeName)) {
        database.clear(storeName);
      }
      database.createObjectStore(storeName);
    },
    terminated: onTerminated,
  });
};

async function _getValue<T>(
  db: Database,
  storeName: string,
  key: IDBValidKey,
): Promise<T | undefined> {
  return await db.get(storeName, key);
}

async function _setValue<T>(
  db: Database,
  storeName: string,
  key: IDBValidKey,
  value: T,
): Promise<IDBValidKey> {
  return await db.put(storeName, value, key);
}

async function _removeValue(db: Database, storeName: string, key: IDBValidKey): Promise<void> {
  return await db.delete(storeName, key);
}

export type DBCreateOptions = {
  dbName?: string;
  storeName?: string;
  version?: number;
};

/**
 * Simple Key Value store
 * Defaults to `'auth-client-db'` with an object store of `'ic-keyval'`
 */
export class IdbKeyVal {
  /**
   * @param {DBCreateOptions} options - DBCreateOptions
   * @param {DBCreateOptions['dbName']} options.dbName name for the indexeddb database
   * @default
   * @param {DBCreateOptions['storeName']} options.storeName name for the indexeddb Data Store
   * @default
   * @param {DBCreateOptions['version']} options.version version of the database. Increment to safely upgrade
   */
  public static async create(options?: DBCreateOptions): Promise<IdbKeyVal> {
    const {
      dbName = AUTH_DB_NAME,
      storeName = OBJECT_STORE_NAME,
      version = DB_VERSION,
    } = options ?? {};
    const keyVal = new IdbKeyVal(dbName, storeName, version);
    // Open eagerly so an unavailable database fails at creation time.
    await keyVal._openDb();
    return keyVal;
  }

  private _dbPromise: Promise<Database> | null = null;

  // Do not use - instead prefer create
  private constructor(
    private _dbName: string,
    private _storeName: string,
    private _version: number,
  ) {}

  // The browser can force-close the connection at any time; the `terminated`
  // hook drops it so the next operation opens a fresh one.
  private _openDb(): Promise<Database> {
    if (this._dbPromise === null) {
      const promise = _openDbStore(this._dbName, this._storeName, this._version, () => {
        if (this._dbPromise === promise) {
          this._dbPromise = null;
        }
      }).catch((error) => {
        if (this._dbPromise === promise) {
          this._dbPromise = null;
        }
        throw error;
      });
      this._dbPromise = promise;
    }
    return this._dbPromise;
  }

  // Chrome can force-close a connection without firing `terminated`; the next
  // transaction then throws an InvalidStateError. Drop the dead connection and
  // retry once on a fresh one.
  private async _withDb<T>(action: (db: Database) => Promise<T>): Promise<T> {
    const promise = this._openDb();
    const db = await promise;
    try {
      return await action(db);
    } catch (error) {
      // Matched by name: a DOMException does not inherit from Error.
      const name = error !== null && typeof error === 'object' && 'name' in error && error.name;
      if (name !== 'InvalidStateError') {
        throw error;
      }
      if (this._dbPromise === promise) {
        this._dbPromise = null;
      }
      return await action(await this._openDb());
    }
  }

  /**
   * Basic setter
   * @param {IDBValidKey} key string | number | Date | BufferSource | IDBValidKey[]
   * @param value value to set
   * @returns void
   */
  public async set<T>(key: IDBValidKey, value: T) {
    return await this._withDb((db) => _setValue<T>(db, this._storeName, key, value));
  }
  /**
   * Basic getter
   * Pass in a type T for type safety if you know the type the value will have if it is found
   * @param {IDBValidKey} key string | number | Date | BufferSource | IDBValidKey[]
   * @returns `Promise<T | null>`
   * @example
   * await get<string>('exampleKey') -> 'exampleValue'
   */
  public async get<T>(key: IDBValidKey): Promise<T | null> {
    return await this._withDb(async (db) => (await _getValue<T>(db, this._storeName, key)) ?? null);
  }

  /**
   * Remove a key
   * @param key {@link IDBValidKey}
   * @returns void
   */
  public async remove(key: IDBValidKey) {
    return await this._withDb((db) => _removeValue(db, this._storeName, key));
  }
}
