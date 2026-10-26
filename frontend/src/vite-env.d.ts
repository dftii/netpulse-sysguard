/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Backend origin, e.g. "http://127.0.0.1:8000". Defaults to http://127.0.0.1:8000. */
  readonly VITE_API_BASE_URL?: string;
  /** Force a mode at startup: "backend", "simulation" or "auto" (default). */
  readonly VITE_DEFAULT_MODE?: "backend" | "simulation" | "auto";
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
