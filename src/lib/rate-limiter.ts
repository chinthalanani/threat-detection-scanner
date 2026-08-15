interface RateLimitEntry {
  count: number;
  resetTime: number;
}

const memoryStore = new Map<string, RateLimitEntry>();

// Cleanup stale entries every 5 minutes
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    memoryStore.forEach((entry, key) => {
      if (entry.resetTime < now) {
        memoryStore.delete(key);
      }
    });
  }, 5 * 60 * 1000);
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetInSeconds: number;
}

/**
 * In-memory sliding window rate limiter
 * @param identifier IP or client key
 * @param limit Max requests within window
 * @param windowSeconds Window duration in seconds
 */
export function checkRateLimit(
  identifier: string,
  limit = 20,
  windowSeconds = 60
): RateLimitResult {
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  const entry = memoryStore.get(identifier);

  if (!entry || entry.resetTime < now) {
    memoryStore.set(identifier, {
      count: 1,
      resetTime: now + windowMs,
    });
    return {
      allowed: true,
      remaining: limit - 1,
      resetInSeconds: windowSeconds,
    };
  }

  if (entry.count >= limit) {
    const resetInSeconds = Math.ceil((entry.resetTime - now) / 1000);
    return {
      allowed: false,
      remaining: 0,
      resetInSeconds: Math.max(1, resetInSeconds),
    };
  }

  entry.count += 1;
  const resetInSeconds = Math.ceil((entry.resetTime - now) / 1000);

  return {
    allowed: true,
    remaining: limit - entry.count,
    resetInSeconds: Math.max(1, resetInSeconds),
  };
}
