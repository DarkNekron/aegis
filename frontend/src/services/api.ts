// Minimal, typed API client. The session lives in an HttpOnly cookie the page cannot read; the CSRF token is
// kept in memory only (never localStorage) and re-issued by /api/auth/csrf after a reload.

import type { Job } from "./types";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public requestId?: string) {
    super(message);
  }
}

let csrfToken: string | null = null;
let onUnauthenticated: (() => void) | null = null;

export function setCsrfToken(token: string | null): void { csrfToken = token; }
export function setUnauthenticatedHandler(handler: () => void): void { onUnauthenticated = handler; }

type Query = Record<string, string | number | boolean | null | undefined>;

function url(path: string, query?: Query): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function request<T>(method: string, path: string, init: { query?: Query; json?: unknown; body?: BodyInit; contentType?: string } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  let body: BodyInit | undefined = init.body;
  if (init.json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(init.json); }
  if (init.contentType) headers["Content-Type"] = init.contentType;

  const response = await fetch(url(path, init.query), { method, headers, body, credentials: "same-origin" });
  if (response.status === 401 && !path.startsWith("/api/auth/login")) onUnauthenticated?.();
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const err = data?.error ?? {};
    throw new ApiError(response.status, err.code ?? `http_${response.status}`, err.message ?? response.statusText, err.request_id);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, query?: Query) => request<T>("GET", path, { query }),
  post: <T>(path: string, json?: unknown, query?: Query) => request<T>("POST", path, { json: json ?? {}, query }),
  put: <T>(path: string, json: unknown) => request<T>("PUT", path, { json }),
  patch: <T>(path: string, json: unknown) => request<T>("PATCH", path, { json }),
  del: <T>(path: string) => request<T>("DELETE", path),
  /** Upload a file as the raw request body (the server enforces the size limit while streaming). */
  upload: <T>(path: string, file: File, query: Query) =>
    request<T>("POST", path, { body: file, query, contentType: "application/octet-stream" }),
};

/** Poll a background job until it finishes. */
export async function waitForJob(jobId: string, onUpdate?: (job: Job) => void, signal?: AbortSignal): Promise<Job> {
  for (;;) {
    if (signal?.aborted) throw new ApiError(0, "aborted", "Stopped waiting for the job.");
    const job = await api.get<Job>(`/api/jobs/${jobId}`);
    onUpdate?.(job);
    if (!["queued", "running"].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, 600));
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Unexpected error.";
}
