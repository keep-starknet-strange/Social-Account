// Shared by the api handlers: an error that carries its HTTP status, and a request limiter.

/** Thrown by a handler to answer with `status` and `{ error: message }`. */
export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// ponytail: per process; put a real limiter in front when replicated.
const hits = new Map<string, number[]>();

/** True and records a hit when `key` has had fewer than `limit` hits in the last `windowMs`. */
export function allow(key: string, limit: number, windowMs: number, now = Date.now()): boolean {
  const recent = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
  if (recent.length >= limit) {
    hits.set(key, recent);
    return false;
  }
  recent.push(now);
  hits.set(key, recent);
  return true;
}

export const HOUR = 3_600_000;
