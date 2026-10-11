/**
 * WebExtension compatibility wrapper.
 * Provides a single, promise-based API surface that works identically on
 * Chromium (chrome.* callback-based APIs) and Firefox (browser.* promise APIs).
 * No other module should call chrome.* or browser.* directly.
 */

type AnyRuntime = typeof chrome;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const runtime: AnyRuntime = (globalThis as any).browser ?? (globalThis as any).chrome;

export const ext = runtime;

function promisify<T>(fn: (cb: (result: T) => void) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    try {
      fn((result: T) => {
        const err = (runtime as any).runtime?.lastError;
        if (err) {
          reject(new Error(err.message ?? String(err)));
          return;
        }
        resolve(result);
      });
    } catch (e) {
      reject(e);
    }
  });
}

function isPromiseNative(): boolean {
  // Firefox's browser.* namespace returns promises natively when no callback given.
  return typeof (globalThis as any).browser !== "undefined";
}

export const storage = {
  async get<T = Record<string, unknown>>(
    keys: string | string[] | Record<string, unknown> | null,
  ): Promise<T> {
    if (isPromiseNative()) {
      return (runtime.storage.local.get as any)(keys) as Promise<T>;
    }
    return promisify<T>((cb) => runtime.storage.local.get(keys as any, cb as any));
  },
  async set(items: Record<string, unknown>): Promise<void> {
    if (isPromiseNative()) {
      return (runtime.storage.local.set as any)(items) as Promise<void>;
    }
    return promisify<void>((cb) => runtime.storage.local.set(items, cb as any));
  },
  async remove(keys: string | string[]): Promise<void> {
    if (isPromiseNative()) {
      return (runtime.storage.local.remove as any)(keys) as Promise<void>;
    }
    return promisify<void>((cb) => runtime.storage.local.remove(keys as any, cb as any));
  },
  onChanged: {
    addListener(
      cb: (changes: Record<string, chrome.storage.StorageChange>, areaName: string) => void,
    ) {
      runtime.storage.onChanged.addListener(cb as any);
    },
  },
};

export const tabsApi = {
  async query(queryInfo: chrome.tabs.QueryInfo): Promise<chrome.tabs.Tab[]> {
    if (isPromiseNative()) {
      return (runtime.tabs.query as any)(queryInfo) as Promise<chrome.tabs.Tab[]>;
    }
    return promisify<chrome.tabs.Tab[]>((cb) => runtime.tabs.query(queryInfo, cb as any));
  },
  async get(tabId: number): Promise<chrome.tabs.Tab> {
    if (isPromiseNative()) {
      return (runtime.tabs.get as any)(tabId) as Promise<chrome.tabs.Tab>;
    }
    return promisify<chrome.tabs.Tab>((cb) => runtime.tabs.get(tabId, cb as any));
  },
  async sendMessage<T = unknown, R = unknown>(tabId: number, message: T): Promise<R> {
    if (isPromiseNative()) {
      return (runtime.tabs.sendMessage as any)(tabId, message) as Promise<R>;
    }
    return promisify<R>((cb) => runtime.tabs.sendMessage(tabId, message as any, cb as any));
  },
  async create(createProperties: chrome.tabs.CreateProperties): Promise<chrome.tabs.Tab> {
    if (isPromiseNative()) {
      return (runtime.tabs.create as any)(createProperties) as Promise<chrome.tabs.Tab>;
    }
    return promisify<chrome.tabs.Tab>((cb) => runtime.tabs.create(createProperties, cb as any));
  },
  async captureVisibleTab(
    windowId?: number,
    options: { format?: "png" | "jpeg"; quality?: number } = { format: "png" },
  ): Promise<string> {
    if (isPromiseNative()) {
      return (runtime.tabs.captureVisibleTab as any)(windowId, options) as Promise<string>;
    }
    return promisify<string>((cb) =>
      runtime.tabs.captureVisibleTab(windowId as any, options as any, cb as any),
    );
  },
  onActivated: {
    addListener(cb: (activeInfo: chrome.tabs.TabActiveInfo) => void) {
      runtime.tabs.onActivated.addListener(cb as any);
    },
  },
  onUpdated: {
    addListener(
      cb: (tabId: number, changeInfo: chrome.tabs.TabChangeInfo, tab: chrome.tabs.Tab) => void,
    ) {
      runtime.tabs.onUpdated.addListener(cb as any);
    },
  },
  onRemoved: {
    addListener(cb: (tabId: number) => void) {
      runtime.tabs.onRemoved.addListener(cb as any);
    },
  },
};

export const runtimeApi = {
  async sendMessage<T = unknown, R = unknown>(message: T): Promise<R> {
    if (isPromiseNative()) {
      return (runtime.runtime.sendMessage as any)(message) as Promise<R>;
    }
    return promisify<R>((cb) => runtime.runtime.sendMessage(message as any, cb as any));
  },
  onMessage: {
    addListener(
      cb: (
        message: any,
        sender: chrome.runtime.MessageSender,
        sendResponse: (response?: any) => void,
      ) => boolean | void,
    ) {
      runtime.runtime.onMessage.addListener(cb as any);
    },
  },
  onStartup: {
    /** Browser launch — the natural point to enforce the retention policy. */
    addListener(cb: () => void) {
      runtime.runtime.onStartup?.addListener(cb as any);
    },
  },
  onInstalled: {
    addListener(cb: () => void) {
      runtime.runtime.onInstalled?.addListener(cb as any);
    },
  },
  getURL(path: string): string {
    return runtime.runtime.getURL(path);
  },
};

export const actionApi = {
  async setBadgeText(details: chrome.action.BadgeTextDetails): Promise<void> {
    const api = (runtime as any).action ?? (runtime as any).browserAction;
    if (isPromiseNative()) {
      return api.setBadgeText(details);
    }
    return promisify<void>((cb) => api.setBadgeText(details, cb));
  },
  async setBadgeBackgroundColor(details: chrome.action.BadgeBackgroundColorDetails): Promise<void> {
    const api = (runtime as any).action ?? (runtime as any).browserAction;
    if (isPromiseNative()) {
      return api.setBadgeBackgroundColor(details);
    }
    return promisify<void>((cb) => api.setBadgeBackgroundColor(details, cb));
  },
  async setTitle(details: chrome.action.TitleDetails): Promise<void> {
    const api = (runtime as any).action ?? (runtime as any).browserAction;
    if (isPromiseNative()) {
      return api.setTitle(details);
    }
    return promisify<void>((cb) => api.setTitle(details, cb));
  },
};

export const notificationsApi = {
  /**
   * Desktop alert for high-risk detections. Firefox exposes the same
   * `notifications` surface through the `browser` namespace, so the wrapper
   * keeps the extension free of engine-specific calls.
   */
  create(
    options: { type: string; iconUrl?: string; title: string; message: string } & Record<
      string,
      unknown
    >,
  ): Promise<string> {
    const api = (runtime as any).notifications;
    if (!api) return Promise.resolve("");
    if (isPromiseNative()) {
      return api.create("", options) as Promise<string>;
    }
    return new Promise<string>((resolve) => {
      api.create("", options, (id: string) => resolve(id ?? ""));
    });
  },
};

export const scriptingApi = {
  async executeScript<T = unknown>(
    injection: chrome.scripting.ScriptInjection<any[], T>,
  ): Promise<chrome.scripting.InjectionResult<T>[]> {
    if (isPromiseNative()) {
      return (runtime as any).scripting.executeScript(injection);
    }
    return promisify((cb) => (runtime as any).scripting.executeScript(injection, cb));
  },
};
