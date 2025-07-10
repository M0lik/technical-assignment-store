import { JSONArray, JSONObject, JSONPrimitive } from "./json-types";

export type Permission = "r" | "w" | "rw" | "none";

export type StoreResult = Store | JSONPrimitive | undefined;

export type StoreValue =
  | JSONObject
  | JSONArray
  | StoreResult
  | (() => StoreResult);

export interface IStore {
  defaultPolicy: Permission;
  allowedToRead(key: string): boolean;
  allowedToWrite(key: string): boolean;
  read(path: string): StoreResult;
  write(path: string, value: StoreValue): StoreValue;
  writeEntries(entries: JSONObject): void;
  entries(): JSONObject;
}

const RESTRICT_METADATA_KEY = Symbol("restrict:permissions");

export function Restrict(permission: Permission = "none"): PropertyDecorator {
  return (target: Object, propertyKey: string | symbol) => {
    const ctor = target.constructor as any;
    if (!ctor.hasOwnProperty(RESTRICT_METADATA_KEY)) {
      ctor[RESTRICT_METADATA_KEY] = {};
    }
    ctor[RESTRICT_METADATA_KEY][propertyKey] = permission;
  };
}

export function getFieldPermissions(ctor: any): Record<string, Permission> {
  return ctor[RESTRICT_METADATA_KEY] || null;
}

export class Store implements IStore {
  defaultPolicy: Permission = "rw";

  //use of internal data to avoid security conflict on this layer
  //prevent: store.write("defaultPolicy", "none");
  private _data: Record<string, any> = {};

  private getPermissions(key: string): Permission {
    const permissions = getFieldPermissions(this.constructor);
    if (permissions && permissions.hasOwnProperty(key)) {
      return permissions[key];
    }
    return this.defaultPolicy;
  }

  allowedToRead(key: string): boolean {
    const perm = this.getPermissions(key);
    return perm === "r" || perm === "rw";
  }

  allowedToWrite(key: string): boolean {
    const perm = this.getPermissions(key);
    return perm === "w" || perm === "rw";
  }

  read(path: string): StoreResult {
    const parts = path.split(":");
    let obj: any = this;

    for (const key of parts) {
      if (!obj.allowedToRead(key)) {
        throw new Error(`Read access denied for key: ${key}`);
      }

      let val = obj[key];
      if (typeof val === "function") {
        val = val();
      } else if (val === undefined && obj._data?.[key] !== undefined) {
        val = obj._data[key];
      }

      if (val === undefined) {
        return undefined;
      }

      obj = val;
    }

    return obj;
  }


  write(path: string, value: StoreValue): StoreValue {
    const parts = path.split(":");
    let obj: any = this;

    //we stop before last item, which will never be a path
    for (const key of parts.slice(0, -1)) {
      if (!obj.allowedToRead(key)) {
        throw new Error(`Write access denied for key: ${key}`);
      }

      let val = typeof obj[key] === "function" ? obj[key]() : obj[key];
      if (val === undefined && obj._data?.[key] !== undefined) {
        val = obj._data[key];
      }
      if (val === undefined) {
        val = new Store();
        if (obj._data) obj._data[key] = val;
      }

      if (val && typeof val === "object" && !(val instanceof Store)) {
        const storeVal = new Store();
        storeVal.writeEntries(val);
        val = storeVal;
        if (obj._data) obj._data[key] = val;
      }

      obj = val;
    }

    const lastKey = parts[parts.length - 1];

    if (!obj.allowedToWrite(lastKey)) {
      throw new Error(`Write access denied for key: ${lastKey}`);
    }

    let toStore = value;
    if (toStore &&
      typeof toStore === "object" &&
      !(toStore instanceof Store) &&
      !Array.isArray(toStore) &&
      typeof toStore !== "function") {
      const storeVal = new Store();
      storeVal.writeEntries(toStore as JSONObject);
      toStore = storeVal;
    }

    if (obj.hasOwnProperty(lastKey)) {
      obj[lastKey] = toStore;
    } else if (obj._data) {
      obj._data[lastKey] = toStore;
    } else {
      obj[lastKey] = toStore;
    }

    return value;
  }


  writeEntries(entries: JSONObject): void {
    for (const [key, val] of Object.entries(entries)) {
      let toWrite: StoreValue = val;
      if (toWrite &&
        typeof toWrite === "object" &&
        !(toWrite instanceof Store) &&
        !Array.isArray(toWrite) &&
        typeof toWrite !== "function") {
        const storeVal = new Store();
        storeVal.writeEntries(toWrite as JSONObject);
        toWrite = storeVal;
      }
      this.write(key, toWrite);
    }
  }

  entries(): JSONObject {
    const result: JSONObject = {};

    for (const [key, val] of Object.entries(this)) {
      if (this.allowedToRead(key) && typeof val !== "function") {
        result[key] = val;
      }
    }

    for (const [key, val] of Object.entries(this._data)) {
      if (this.allowedToRead(key)) {
        result[key] = val;
      }
    }

    return result;
  }
}
