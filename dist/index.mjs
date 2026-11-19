// src/run.ts
import { execFileSync } from "node:child_process";
import { randomUUID as randomUUID2 } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";

// ../sdk/src/grant.ts
import { verify } from "node:crypto";

// ../sdk/src/canonical.ts
import { createHash } from "node:crypto";
function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Cannot canonicalize a non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => {
      if (item === void 0) throw new TypeError("Cannot canonicalize undefined in an array.");
      return canonicalize(item);
    }).join(",")}]`;
  }
  const prototype = typeof value === "object" ? Object.getPrototypeOf(value) : void 0;
  if (prototype !== Object.prototype && prototype !== null) {
    const kind = prototype?.constructor?.name ?? typeof value;
    throw new TypeError(`Cannot canonicalize a ${kind}; pass plain JSON values.`);
  }
  const object = value;
  const keys = Object.keys(object).filter((key) => object[key] !== void 0).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(object[key])}`).join(",")}}`;
}
function payloadHash(payload) {
  return createHash("sha256").update(canonicalize(payload)).digest("hex");
}

// ../sdk/src/errors.ts
var DueReasonError = class extends Error {
  name = "DueReasonError";
};
var DueReasonApiError = class extends DueReasonError {
  constructor(status, code, message, details = null, retryAfterSeconds = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfterSeconds = retryAfterSeconds;
  }
  status;
  code;
  details;
  retryAfterSeconds;
  name = "DueReasonApiError";
};
var GrantVerificationError = class extends DueReasonError {
  constructor(reason, message) {
    super(message);
    this.reason = reason;
  }
  reason;
  name = "GrantVerificationError";
};

// ../sdk/src/jwks.ts
import { createPublicKey } from "node:crypto";
var JWKS_TTL_MS = 5 * 60 * 1e3;
var JWKS_MIN_REFRESH_MS = 30 * 1e3;
var JWKS_FETCH_TIMEOUT_MS = 1e4;
var jwksCache = /* @__PURE__ */ new Map();
var JwksFetchError = class extends DueReasonError {
  name = "JwksFetchError";
};
function defaultJwksUrl(baseUrl, organization) {
  return `${baseUrl.replace(/\/+$/, "")}/.well-known/duereason/${encodeURIComponent(organization)}/jwks.json`;
}
function loadKeys(url, fetchImpl, now) {
  const entry = {
    fetchedAt: now,
    keys: (async () => {
      const response = await fetchImpl(url, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS)
      });
      if (!response.ok) {
        throw new JwksFetchError(`Fetching the JWKS from ${url} failed: HTTP ${response.status}.`);
      }
      const listed = (await response.json())?.keys;
      const keys = /* @__PURE__ */ new Map();
      for (const jwk of Array.isArray(listed) ? listed : []) {
        const { kty, crv, x, kid, alg, use } = jwk ?? {};
        if (kty !== "OKP" || crv !== "Ed25519" || typeof x !== "string" || typeof kid !== "string")
          continue;
        if (alg !== void 0 && alg !== "EdDSA" || use !== void 0 && use !== "sig")
          continue;
        try {
          keys.set(kid, createPublicKey({ key: { kty, crv, x }, format: "jwk" }));
        } catch {
        }
      }
      return keys;
    })()
  };
  jwksCache.set(url, entry);
  entry.keys.catch(() => {
    if (jwksCache.get(url) === entry) jwksCache.delete(url);
  });
  return entry;
}
async function signingKey(url, kid, fetchImpl) {
  const now = Date.now();
  let cached = jwksCache.get(url);
  if (!cached || now - cached.fetchedAt > JWKS_TTL_MS) cached = loadKeys(url, fetchImpl, now);
  const key = (await cached.keys).get(kid);
  if (key || now - cached.fetchedAt < JWKS_MIN_REFRESH_MS) return key;
  return (await loadKeys(url, fetchImpl, now).keys).get(kid);
}

// ../sdk/src/grant.ts
var DEFAULT_BASE_URL = "https://duereason.com";
var GRANT_TYPE = "duereason-grant+jwt";
var SEGMENT = /^[A-Za-z0-9_-]+$/;
async function verifyGrant(options) {
  const parts = options.grant.split(".");
  if (parts.length !== 3 || !parts.every((part) => SEGMENT.test(part))) {
    throw new GrantVerificationError("malformed", "The grant is not a compact JWS.");
  }
  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const header = decodeJson(encodedHeader);
  if (header?.alg !== "EdDSA" || header.typ !== GRANT_TYPE || typeof header.kid !== "string" || header.kid === "" || "crit" in header) {
    throw new GrantVerificationError(
      "malformed",
      `The grant header is not an EdDSA ${GRANT_TYPE} header with a kid.`
    );
  }
  const signature = Buffer.from(encodedSignature, "base64url");
  if (signature.length !== 64)
    throw new GrantVerificationError("malformed", "The grant signature is not Ed25519.");
  const jwksUrl = options.jwksUrl ?? defaultJwksUrl(options.baseUrl ?? DEFAULT_BASE_URL, options.organization);
  const key = await signingKey(jwksUrl, header.kid, options.fetch ?? fetch);
  if (!key)
    throw new GrantVerificationError("unknown_key", `No published key has the id ${header.kid}.`);
  const signed = Buffer.from(`${encodedHeader}.${encodedClaims}`, "ascii");
  if (!verify(null, signed, key, signature)) {
    throw new GrantVerificationError("bad_signature", "The grant signature does not verify.");
  }
  const claims = decodeJson(encodedClaims);
  if (!claims || !isGrantClaims(claims))
    throw new GrantVerificationError("malformed", "The grant claims are incomplete.");
  if (claims.exp * 1e3 <= Date.now()) {
    throw new GrantVerificationError(
      "expired",
      `The grant expired at ${new Date(claims.exp * 1e3).toISOString()}.`
    );
  }
  if (claims.org !== options.organization) {
    throw new GrantVerificationError(
      "wrong_organization",
      `The grant was issued by the organization ${claims.org}.`
    );
  }
  if (options.action !== void 0 && claims.act !== options.action) {
    throw new GrantVerificationError(
      "wrong_action",
      `The grant approves the action ${claims.act}.`
    );
  }
  if (claims.ph !== payloadHash(options.payload)) {
    throw new GrantVerificationError(
      "payload_mismatch",
      "The payload differs from the one that was approved."
    );
  }
  return claims;
}
function decodeJson(segment) {
  try {
    const value = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}
function isGrantClaims(claims) {
  return ["iss", "org", "sub", "jti", "act", "ph"].every((name) => typeof claims[name] === "string") && Array.isArray(claims.apv) && claims.apv.every((id) => typeof id === "string") && Number.isInteger(claims.iat) && Number.isInteger(claims.exp);
}

// ../sdk/src/client.ts
import { randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

// ../sdk/src/types.ts
var TERMINAL_STATUS = {
  pending: false,
  approved: true,
  rejected: true,
  expired: true,
  cancelled: true
};

// ../sdk/src/client.ts
var MAX_WAIT_SECONDS = 20;
var AUTH_SCHEME = "Bearer";
function authHeader(apiKey) {
  return [AUTH_SCHEME, apiKey].join(" ");
}
var UPLOAD_GRACE_MS_PER_MB = 2e3;
function attachmentBytes(file) {
  return file.data instanceof Blob ? file.data.size : file.data.byteLength;
}
function uploadGraceMs(files) {
  const totalBytes = files.reduce((sum, file) => sum + attachmentBytes(file), 0);
  return Math.ceil(totalBytes / (1024 * 1024) * UPLOAD_GRACE_MS_PER_MB);
}
var REQUEST_GRACE_MS = 3e4;
var MAX_BACKOFF_MS = 15e3;
var DEFAULT_MAX_RETRIES = 3;
function createClient(options) {
  if (!options.apiKey) throw new TypeError("createClient needs an apiKey.");
  const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? fetch;
  const maxRetries = Math.max(0, options.maxRetries ?? DEFAULT_MAX_RETRIES);
  let rateLimitSnapshot;
  let lastIdempotentReplay;
  async function call(method, path, init = {}) {
    const multipart = method === "POST" && (init.files?.length ?? 0) > 0;
    const headers = {
      Authorization: authHeader(options.apiKey),
      Accept: "application/json"
    };
    if (method === "POST") {
      headers["Idempotency-Key"] = init.idempotencyKey ?? randomUUID();
    }
    if (!multipart && (method === "POST" || method === "PATCH")) {
      headers["Content-Type"] = "application/json";
    }
    const deadline = Date.now() + (init.timeoutMs ?? REQUEST_GRACE_MS);
    let attempt = 0;
    for (; ; ) {
      const timeout = AbortSignal.timeout(Math.max(0, deadline - Date.now()));
      const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
      try {
        const body = multipart ? multipartBody(init.body, init.files) : method === "POST" || method === "PATCH" ? JSON.stringify(init.body ?? {}) : void 0;
        const response = await fetchImpl(`${baseUrl}/api/v1${path}`, {
          method,
          headers,
          body,
          signal
        });
        const observedRateLimit = parseRateLimitHeaders(response.headers);
        if (observedRateLimit) rateLimitSnapshot = observedRateLimit;
        if (method === "POST") {
          lastIdempotentReplay = response.headers.get("idempotent-replayed") === "true";
        }
        const text = await response.text();
        if (response.ok) return JSON.parse(text);
        throw problemError(response, text);
      } catch (error) {
        if (init.signal?.aborted || attempt >= maxRetries || !isTransient(error)) throw error;
        const delay = error instanceof DueReasonApiError && error.retryAfterSeconds !== null ? error.retryAfterSeconds * 1e3 : Math.min(MAX_BACKOFF_MS, 500 * 2 ** attempt);
        attempt += 1;
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw error;
        await sleep(Math.min(delay, remaining), void 0, { signal: init.signal });
      }
    }
  }
  const getApproval = (id, { waitSeconds = 0, signal } = {}) => {
    const wait = Math.min(MAX_WAIT_SECONDS, Math.max(0, Math.ceil(waitSeconds)));
    return call(
      "GET",
      `/approvals/${encodeURIComponent(id)}${wait > 0 ? `?wait=${wait}` : ""}`,
      { signal, timeoutMs: wait * 1e3 + REQUEST_GRACE_MS }
    );
  };
  return {
    get rateLimit() {
      return rateLimitSnapshot;
    },
    get lastIdempotentReplay() {
      return lastIdempotentReplay;
    },
    listActions: (input = {}) => {
      const params = new URLSearchParams();
      if (input.includeInactive) params.set("include", "inactive");
      if (input.cursor) params.set("cursor", input.cursor);
      if (input.limit !== void 0) params.set("limit", String(input.limit));
      const query = params.toString();
      return call("GET", `/actions${query ? `?${query}` : ""}`);
    },
    getAction: (key) => call("GET", `/actions/${encodeURIComponent(key)}`),
    createAction: (input, { idempotencyKey } = {}) => call("POST", "/actions", { body: input, idempotencyKey }),
    updateAction: (key, input) => call("PATCH", `/actions/${encodeURIComponent(key)}`, { body: input }),
    listWorkflows: (input = {}) => {
      const params = new URLSearchParams();
      if (input.action) params.set("action", input.action);
      if (input.cursor) params.set("cursor", input.cursor);
      if (input.limit !== void 0) params.set("limit", String(input.limit));
      const query = params.toString();
      return call("GET", `/workflows${query ? `?${query}` : ""}`);
    },
    getWorkflow: (id) => call("GET", `/workflows/${encodeURIComponent(id)}`),
    createWorkflow: (input, { idempotencyKey } = {}) => call("POST", "/workflows", { body: input, idempotencyKey }),
    updateWorkflow: (id, input) => call("PATCH", `/workflows/${encodeURIComponent(id)}`, { body: input }),
    deleteWorkflow: (id) => call("DELETE", `/workflows/${encodeURIComponent(id)}`),
    requestApproval: (input, { idempotencyKey, files, timeoutMs } = {}) => call("POST", "/approvals", {
      body: input,
      files,
      idempotencyKey,
      timeoutMs: timeoutMs ?? (files?.length ? REQUEST_GRACE_MS + uploadGraceMs(files) : void 0)
    }),
    getApproval,
    listApprovals: (input = {}) => {
      const params = new URLSearchParams();
      if (input.status) params.set("status", input.status);
      if (input.action) params.set("action", input.action);
      if (input.payloadHash) params.set("payloadHash", input.payloadHash);
      if (input.cursor) params.set("cursor", input.cursor);
      if (input.limit !== void 0) params.set("limit", String(input.limit));
      const query = params.toString();
      return call("GET", `/approvals${query ? `?${query}` : ""}`);
    },
    // Kept as its own loop rather than reusing call()'s fixed attempt cap:
    // this one retries until timeoutMs elapses (not after N attempts), races
    // against the long-poll's own wait window, and must resolve with the
    // last known (still pending) request on timeout instead of throwing —
    // none of which fits call()'s "bounded attempts, deadline from
    // init.timeoutMs" contract without changing its documented behavior.
    async waitForApproval(id, { timeoutMs, signal }) {
      const deadline = Date.now() + timeoutMs;
      let last;
      let failures = 0;
      for (; ; ) {
        const remaining = deadline - Date.now();
        if (last && (TERMINAL_STATUS[last.status] || remaining <= 0)) return last;
        try {
          last = await getApproval(id, { waitSeconds: remaining / 1e3, signal });
          failures = 0;
        } catch (error) {
          if (signal?.aborted || !isTransient(error)) throw error;
          const delay = error instanceof DueReasonApiError && error.retryAfterSeconds !== null ? error.retryAfterSeconds * 1e3 : Math.min(MAX_BACKOFF_MS, 500 * 2 ** failures);
          failures += 1;
          if (Date.now() + delay >= deadline) {
            if (last) return last;
            throw error;
          }
          await sleep(delay, void 0, { signal });
        }
      }
    },
    cancelApproval: (id, { idempotencyKey } = {}) => call("POST", `/approvals/${encodeURIComponent(id)}/cancel`, {
      idempotencyKey
    }),
    reportExecution: (id, report, { idempotencyKey } = {}) => call("POST", `/approvals/${encodeURIComponent(id)}/executions`, {
      body: report,
      idempotencyKey
    }),
    verifyGrant: (verifyOptions) => verifyGrant({ ...verifyOptions, baseUrl, fetch: fetchImpl }),
    checkMandate: (input, { idempotencyKey } = {}) => call("POST", "/mandates/check", { body: input, idempotencyKey }),
    getPrecedents: (id, { limit } = {}) => {
      const params = new URLSearchParams();
      if (limit !== void 0) params.set("limit", String(limit));
      const query = params.toString();
      return call(
        "GET",
        `/approvals/${encodeURIComponent(id)}/precedents${query ? `?${query}` : ""}`
      );
    },
    checkPrecedents: (input, { idempotencyKey } = {}) => call("POST", "/precedents/check", { body: input, idempotencyKey }),
    getReceipt: (id) => call("GET", `/approvals/${encodeURIComponent(id)}/receipt`),
    getLedgerHead: () => call("GET", "/ledger/head"),
    listReceipts: (input) => {
      const params = new URLSearchParams();
      params.set("from", input.from);
      params.set("to", input.to);
      if (input.cursor) params.set("cursor", input.cursor);
      if (input.limit !== void 0) params.set("limit", String(input.limit));
      return call("GET", `/receipts?${params.toString()}`);
    },
    listMandates: async (input = {}) => {
      const params = new URLSearchParams();
      if (input.actionId) params.set("actionId", input.actionId);
      if (input.activeOnly !== void 0) params.set("activeOnly", String(input.activeOnly));
      if (input.cursor) params.set("cursor", input.cursor);
      if (input.limit !== void 0) params.set("limit", String(input.limit));
      const query = params.toString();
      return call("GET", `/mandates${query ? `?${query}` : ""}`);
    },
    getMandate: (id) => call("GET", `/mandates/${encodeURIComponent(id)}`),
    revokeMandate: (id, { reason, idempotencyKey } = {}) => call("POST", `/mandates/${encodeURIComponent(id)}/revoke`, {
      body: { reason },
      idempotencyKey
    }),
    listWebhookEndpoints: async () => (await call("GET", "/webhooks")).data,
    createWebhookEndpoint: (input, { idempotencyKey } = {}) => call("POST", "/webhooks", { body: input, idempotencyKey }),
    updateWebhookEndpoint: (id, input) => call("PATCH", `/webhooks/${encodeURIComponent(id)}`, { body: input }),
    deleteWebhookEndpoint: (id) => call("DELETE", `/webhooks/${encodeURIComponent(id)}`),
    rotateWebhookSecret: (id, { idempotencyKey } = {}) => call("POST", `/webhooks/${encodeURIComponent(id)}/rotate-secret`, {
      idempotencyKey
    }),
    listWebhookDeliveries: (id, { limit, cursor } = {}) => {
      const params = new URLSearchParams();
      if (limit !== void 0) params.set("limit", String(limit));
      if (cursor) params.set("cursor", cursor);
      const query = params.toString();
      return call(
        "GET",
        `/webhooks/${encodeURIComponent(id)}/deliveries${query ? `?${query}` : ""}`
      );
    },
    sendWebhookTest: (id, { idempotencyKey } = {}) => call("POST", `/webhooks/${encodeURIComponent(id)}/test`, {
      idempotencyKey
    }),
    redeliverWebhookDelivery: (deliveryId, { idempotencyKey } = {}) => call(
      "POST",
      `/webhooks/deliveries/${encodeURIComponent(deliveryId)}/redeliver`,
      { idempotencyKey }
    )
  };
}
function multipartBody(body, files) {
  const form = new FormData();
  form.set("request", JSON.stringify(body ?? {}));
  for (const file of files) {
    const blob = file.data instanceof Blob ? file.data : new Blob([Buffer.from(file.data)]);
    form.append("files", blob, file.filename);
  }
  return form;
}
function parseRateLimitHeaders(headers) {
  const limitHeader = headers.get("ratelimit-limit");
  const remainingHeader = headers.get("ratelimit-remaining");
  const resetHeader = headers.get("ratelimit-reset");
  if (limitHeader === null || remainingHeader === null || resetHeader === null) return void 0;
  const limit = Number(limitHeader);
  const remaining = Number(remainingHeader);
  const reset = Number(resetHeader);
  if (!Number.isInteger(limit) || !Number.isInteger(remaining) || !Number.isInteger(reset)) {
    return void 0;
  }
  return { limit, remaining, reset };
}
function problemError(response, text) {
  let problem = {};
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed === "object" && parsed !== null) problem = parsed;
  } catch {
  }
  const code = typeof problem.code === "string" ? problem.code : `http_${response.status}`;
  const message = typeof problem.detail === "string" && problem.detail || typeof problem.title === "string" && problem.title || `DueReason answered HTTP ${response.status}.`;
  const details = typeof problem.details === "object" && problem.details !== null ? problem.details : null;
  const retryAfter = /^\d+$/.test(response.headers.get("retry-after") ?? "") ? Number(response.headers.get("retry-after")) : null;
  return new DueReasonApiError(response.status, code, message, details, retryAfter);
}
function isTransient(error) {
  if (!(error instanceof DueReasonApiError)) return true;
  if (error.status === 429) return true;
  if (error.status === 409 && error.code === "idempotency_key_in_use") return true;
  return error.status >= 500 && error.code !== "grants_unavailable";
}

// ../sdk/src/find-approved.ts
async function findApprovedGrant(client, options) {
  const page = await client.listApprovals({
    action: options.action,
    payloadHash: payloadHash(options.payload),
    status: "approved",
    limit: 1
  });
  const match = page.data[0];
  if (!match?.grant) return null;
  const claims = await client.verifyGrant({
    grant: match.grant,
    payload: options.payload,
    organization: options.organization,
    action: options.action
  });
  return { requestId: match.id, grant: match.grant, claims, console: match.links.console };
}

// src/run.ts
async function run(env, options = {}) {
  const log = options.log ?? ((line) => console.log(line));
  const input = (name) => (env[`INPUT_${name.toUpperCase()}`] ?? "").trim();
  const fail = (message) => {
    log(`::error title=DueReason::${escapeCommand(message)}`);
    return 1;
  };
  const apiKey = input("api-key");
  if (!apiKey)
    return fail(
      "Set the api-key input from a secret: an API key with the approval:request and approval:read scopes."
    );
  log(`::add-mask::${apiKey}`);
  const mode = input("mode") || "request";
  switch (mode) {
    case "request":
      return runRequest(env, input, apiKey, fail, log, options);
    case "verify":
      return runVerify(env, input, apiKey, fail, log, options);
    case "report":
      return runReport(env, input, apiKey, fail, log, options);
    default:
      return fail(`mode must be "request", "verify" or "report"; got "${mode}".`);
  }
}
async function runRequest(env, input, apiKey, fail, log, options) {
  const reason = input("reason");
  if (!reason) return fail("Set the reason input: why this should happen. Approvers decide on it.");
  const timeoutMinutes = Number(input("timeout-minutes") || "60");
  if (!Number.isFinite(timeoutMinutes) || timeoutMinutes <= 0 || timeoutMinutes > 10080) {
    return fail("timeout-minutes must be a number of minutes between 1 and 10080 (7 days).");
  }
  const action = input("action") || "deployment";
  const environment = input("environment") || "production";
  const repository = env.GITHUB_REPOSITORY ?? "";
  const sha = env.GITHUB_SHA ?? "";
  const resolved = resolvePayload(input, env);
  if ("error" in resolved) return fail(resolved.error);
  const { payload } = resolved;
  const title = input("title") || defaultTitle(env, action, environment);
  const runUrl = `${env.GITHUB_SERVER_URL ?? "https://github.com"}/${repository}/actions/runs/${env.GITHUB_RUN_ID}`;
  const client = createClient({
    apiKey,
    baseUrl: input("url") || void 0,
    fetch: options.fetch
  });
  const agent = {
    name: "github-actions",
    repository,
    ref: env.GITHUB_REF,
    workflow: env.GITHUB_WORKFLOW,
    runId: env.GITHUB_RUN_ID,
    actor: env.GITHUB_ACTOR
  };
  let mandateCoverage = null;
  if (input("mandate-check") !== "false") {
    try {
      const mandate = await client.checkMandate({ actionKey: action, payload, agent });
      if (mandate.covered && mandate.mandate) {
        mandateCoverage = { id: mandate.mandate.id };
        log(
          `Mandate ${mandate.mandate.id} covers this; filing the request, it approves instantly and uses 1 of ${mandateRemaining(mandate.remaining)} remaining.`
        );
      }
    } catch (error) {
      if (error instanceof DueReasonApiError && error.code === "insufficient_scope") {
        log(
          `::notice title=DueReason::Skipping the mandate pre-check: this API key lacks the optional mandate:read scope. Add it to see mandate coverage logged in advance, or set mandate-check: "false" to silence this notice.`
        );
      } else {
        log(
          `::warning title=DueReason::Checking mandate coverage failed, requesting approval as usual: ${escapeCommand(describe(error))}`
        );
      }
    }
  }
  const withdraw = async (pending) => {
    try {
      return await client.cancelApproval(pending.id);
    } catch (error) {
      if (error instanceof DueReasonApiError && error.code === "not_pending") {
        return client.getApproval(pending.id);
      }
      throw error;
    }
  };
  let request;
  try {
    request = await client.requestApproval(
      {
        action,
        title,
        reason,
        payload,
        agent,
        context: repository ? [
          { label: "Workflow run", url: runUrl },
          ...sha ? [
            {
              label: "Commit",
              url: `${env.GITHUB_SERVER_URL ?? "https://github.com"}/${repository}/commit/${sha}`
            }
          ] : []
        ] : void 0,
        // Expires when this job stops waiting (the API minimum is 60 s).
        expiresInSeconds: Math.min(604800, Math.max(60, Math.ceil(timeoutMinutes * 60)))
      },
      {
        // Stable across "re-run failed jobs" (same GITHUB_RUN_ID, only run_attempt changes), so a
        // retried step replays the first request instead of opening a duplicate one. `action` keeps
        // two DueReason steps in the same run (e.g. staging + production) from colliding.
        idempotencyKey: `gha:${repository}:${env.GITHUB_RUN_ID}:${action}`
      }
    );
  } catch (error) {
    return fail(`Requesting approval failed: ${describe(error)}`);
  }
  setOutput(env, "request-id", request.id);
  log(`Approval requested: ${request.links.console}`);
  let mandateApprovedId = null;
  if (mandateCoverage) {
    if (request.status !== "pending") {
      mandateApprovedId = mandateCoverage.id;
    } else {
      log(
        `::notice title=DueReason::Mandate ${mandateCoverage.id} looked like it covered this, but the request is still pending (its budget changed meanwhile); waiting for a decision as usual.`
      );
    }
  }
  let outcome;
  try {
    request = await client.waitForApproval(request.id, {
      timeoutMs: timeoutMinutes * 6e4,
      signal: options.signal
    });
    outcome = request.status;
    if (outcome === "pending") {
      request = await withdraw(request);
      outcome = request.status === "cancelled" ? "timeout" : request.status;
    }
  } catch (error) {
    if (options.signal?.aborted) {
      await withdraw(request).catch(() => void 0);
      return fail("The job was cancelled; the approval request was withdrawn.");
    }
    return fail(`Waiting for approval failed: ${describe(error)}`);
  }
  setOutput(env, "status", outcome);
  if (request.grant && outcome === "approved") setOutput(env, "grant", request.grant);
  if (mandateApprovedId && outcome === "approved") setOutput(env, "mandate-id", mandateApprovedId);
  summarize(
    env,
    request,
    outcome,
    timeoutMinutes,
    outcome === "approved" ? mandateApprovedId : null
  );
  const rejection = request.responses.find((response) => response.verdict === "rejected");
  switch (outcome) {
    case "approved":
      log(`Approved: ${request.links.console}`);
      return 0;
    case "rejected":
      return fail(
        `Rejected by ${rejection?.approver.name ?? "an approver"}: ${rejection?.comment ?? ""} (${request.links.console})`
      );
    case "timeout":
      return fail(`No decision within ${timeoutMinutes} minutes; the request was withdrawn.`);
    default:
      return fail(`The approval request was ${outcome}. (${request.links.console})`);
  }
}
async function runVerify(env, input, apiKey, fail, log, options) {
  const organization = input("organization");
  if (!organization) return fail("Set the organization input: your DueReason organization slug.");
  const resolved = resolvePayload(input, env);
  if ("error" in resolved) return fail(resolved.error);
  const { payload } = resolved;
  const action = input("action") || "deployment";
  const client = createClient({
    apiKey,
    baseUrl: input("url") || void 0,
    fetch: options.fetch
  });
  const grant = input("grant");
  if (grant) {
    let claims;
    try {
      claims = await client.verifyGrant({ grant, payload, organization, action });
    } catch (error) {
      if (error instanceof GrantVerificationError) {
        return fail(`The grant does not authorize this: ${error.reason}: ${error.message}`);
      }
      return fail(`Verifying the grant failed: ${describe(error)}`);
    }
    setOutput(env, "request-id", claims.sub);
    summarizeOneLine(env, `Grant for \`${claims.sub}\` verified for this payload.`);
    log(`Grant verified: ${claims.sub}.`);
    return 0;
  }
  let found;
  try {
    found = await findApprovedGrant(client, { action, payload, organization });
  } catch (error) {
    if (error instanceof GrantVerificationError) {
      return fail(
        `An approved request exists for this payload, but its grant does not authorize it: ${error.reason}: ${error.message}. File a new request and get it approved again.`
      );
    }
    return fail(`Looking up an approved request failed: ${describe(error)}`);
  }
  if (found) {
    setOutput(env, "request-id", found.requestId);
    summarizeOneLine(env, `Grant for \`${found.requestId}\` verified for this payload.`);
    log(`Grant verified: ${found.requestId} (${found.console}).`);
    return 0;
  }
  const consoleBase = (input("url") || "https://duereason.com").replace(/\/$/, "");
  if (input("request-if-missing") === "true") {
    const reason = input("reason");
    if (!reason) {
      return fail(
        "Set the reason input: request-if-missing files a request when none is approved yet, and DueReason requires a reason."
      );
    }
    const environment = input("environment") || "production";
    const repository = env.GITHUB_REPOSITORY ?? "";
    const title = input("title") || defaultTitle(env, action, environment);
    const runUrl = `${env.GITHUB_SERVER_URL ?? "https://github.com"}/${repository}/actions/runs/${env.GITHUB_RUN_ID}`;
    let request;
    try {
      request = await client.requestApproval(
        {
          action,
          title,
          reason,
          payload,
          agent: {
            name: "github-actions",
            repository,
            ref: env.GITHUB_REF,
            workflow: env.GITHUB_WORKFLOW,
            runId: env.GITHUB_RUN_ID,
            actor: env.GITHUB_ACTOR
          },
          context: repository ? [{ label: "Workflow run", url: runUrl }] : void 0
        },
        // Distinct from mode request's key (suffixed `:verify`): the two can run in the same
        // workflow run for different purposes and must never collide or replay each other.
        { idempotencyKey: `gha:${repository}:${env.GITHUB_RUN_ID}:${action}:verify` }
      );
    } catch (error) {
      return fail(`Filing the approval request failed: ${describe(error)}`);
    }
    setOutput(env, "request-id", request.id);
    summarizeOneLine(
      env,
      `No approved request yet; filed \`${request.id}\`, waiting for approval.`
    );
    return fail(
      `No approved request for this payload yet; filed ${request.id} and it is waiting for approval: ${request.links.console}. Re-run this check once it is approved.`
    );
  }
  return fail(
    `No approved request found for action "${action}" with this exact payload. File one in DueReason and get it approved, then re-run this check: ${consoleBase}/app/approvals`
  );
}
async function runReport(env, input, apiKey, fail, log, options) {
  const requestId = input("request-id");
  if (!requestId)
    return fail("Set the request-id input: the request-id output from the request step.");
  const grant = input("grant");
  if (!grant) return fail("Set the grant input: the grant output from the request step.");
  const outcome = input("outcome");
  if (outcome !== "succeeded" && outcome !== "failed") {
    return fail('Set the outcome input to "succeeded" or "failed".');
  }
  const detail = input("detail") || void 0;
  const client = createClient({
    apiKey,
    baseUrl: input("url") || void 0,
    fetch: options.fetch
  });
  try {
    await client.reportExecution(requestId, { grant, outcome, detail });
  } catch (error) {
    if (error instanceof DueReasonApiError && error.code === "already_executed") {
      return fail(
        `already_executed: ${requestId} was already reported executed; a grant is single-use. This step ran twice.`
      );
    }
    return fail(`Reporting the execution failed: ${describe(error)}`);
  }
  summarizeOneLine(env, `Execution of \`${requestId}\` reported as ${outcome}.`);
  log(`Execution reported: ${outcome}.`);
  return 0;
}
function defaultTitle(env, action, environment) {
  const repository = env.GITHUB_REPOSITORY ?? "";
  const service = repository.split("/").pop() || repository;
  const sha = env.GITHUB_SHA ?? "";
  return action === "deployment" ? `Deploy ${service} ${sha.slice(0, 7)} to ${environment}` : `${action} from ${env.GITHUB_WORKFLOW ?? "a workflow"} in ${repository}`;
}
function resolvePayload(input, env) {
  const environment = input("environment") || "production";
  const repository = env.GITHUB_REPOSITORY ?? "";
  const service = repository.split("/").pop() || repository;
  const sha = env.GITHUB_SHA ?? "";
  if (input("payload")) {
    let payload;
    try {
      payload = JSON.parse(input("payload"));
    } catch {
      return { error: "The payload input is not valid JSON." };
    }
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
      return { error: "The payload input must be a JSON object." };
    }
    return { payload };
  }
  return {
    payload: {
      service,
      environment,
      commit: sha,
      changeSummary: commitMessage(env)?.slice(0, 2e3)
    }
  };
}
function commitMessage(env) {
  if (env.GITHUB_EVENT_PATH) {
    try {
      const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8"));
      const message = event.head_commit?.message ?? event.pull_request?.title;
      if (typeof message === "string" && message.trim()) return message.trim();
    } catch {
    }
  }
  if (!env.GITHUB_WORKSPACE || !env.GITHUB_SHA) return void 0;
  try {
    const message = execFileSync("git", ["log", "-1", "--format=%B", env.GITHUB_SHA], {
      cwd: env.GITHUB_WORKSPACE,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    return message || void 0;
  } catch {
    return void 0;
  }
}
function setOutput(env, name, value) {
  if (!env.GITHUB_OUTPUT) return;
  const delimiter = `duereason_${randomUUID2()}`;
  appendFileSync(env.GITHUB_OUTPUT, `${name}<<${delimiter}
${value}
${delimiter}
`);
}
function summarize(env, request, outcome, timeoutMinutes, mandateId) {
  if (!env.GITHUB_STEP_SUMMARY) return;
  const lines = [
    `### DueReason approval: ${outcome}`,
    "",
    `- **Request:** [${markdown(request.title)}](${request.links.console})`,
    `- **Action:** ${markdown(request.action)}${request.workflow.name ? `, workflow ${markdown(request.workflow.name)} v${request.workflow.version}` : ""}`,
    ...mandateId ? [
      `- **Approved under mandate** \`${mandateId}\`: a request was filed and immediately decided, so it counts against the mandate's limit and has a receipt like any other.`
    ] : [],
    ...request.responses.map(
      (response) => `- **${response.verdict === "approved" ? "Approved" : "Rejected"} by ${markdown(response.approver.name)}**${response.comment ? `: ${markdown(response.comment)}` : ""}`
    ),
    `- **Payload hash:** \`${request.payloadHash}\``,
    outcome === "timeout" ? `
No decision within ${timeoutMinutes} minutes; the request was withdrawn.` : "",
    ""
  ];
  appendFileSync(env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}
`);
}
function summarizeOneLine(env, line) {
  if (!env.GITHUB_STEP_SUMMARY) return;
  appendFileSync(env.GITHUB_STEP_SUMMARY, `DueReason: ${line}
`);
}
function mandateRemaining(remaining) {
  const left = remaining?.count?.remaining ?? remaining?.cumulative?.remaining;
  return left === void 0 ? "an unknown number of" : String(left);
}
function markdown(text) {
  return text.replace(/[\\`*_{}[\]()<>#+!|~]/g, "\\$&").replace(/\s*\n\s*/g, " ");
}
function escapeCommand(text) {
  return text.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}
function describe(error) {
  if (error instanceof DueReasonApiError) return `${error.code}: ${error.message}`;
  if (!(error instanceof Error)) return String(error);
  return error.cause instanceof Error ? `${error.message} (${error.cause.message})` : error.message;
}

// src/main.ts
var cancelled = new AbortController();
process.once("SIGINT", () => cancelled.abort());
process.once("SIGTERM", () => cancelled.abort());
process.exitCode = await run(process.env, { signal: cancelled.signal });
