import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createClient } from "../../sdk/src/client";
import type { ApprovalRequestInput, JsonObject, Mandate } from "../../sdk/src/types";
import { type FakeApi, newKey, signGrant, startFakeApi } from "../../sdk/test/fake-api";
import { run } from "../src/run";

const SHA = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d";
/** Shared signing key, published through `api.jwks` so `verify` can check real grants. */
const key = newKey("gsk_test");

/** A minimal, fully-typed mandate, so `api.checkMandate` can answer `covered: true`. */
function fakeMandate(overrides: Partial<Mandate> = {}): Mandate {
  return {
    id: "mdt_1",
    actionId: "acn_1",
    actionKey: "deployment",
    subject: { type: "agent", id: "github-actions", name: "github-actions" },
    constraints: [],
    cumulativeLimit: null,
    countLimit: { period: "day", max: 10 },
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil: "2026-12-31T00:00:00.000Z",
    reason: "Routine production deploys under 10/day.",
    issuer: { id: "usr_1", name: "Olga Owner" },
    revoked: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    usage: { cumulative: null, count: { period: "day", max: 10, used: 3 } },
    ...overrides,
  };
}
let api: FakeApi;
let dir: string;
let env: Record<string, string>;
let log: string[];

beforeEach(async () => {
  api = await startFakeApi();
  api.jwks.keys.push(key.jwk);
  dir = mkdtempSync(join(tmpdir(), "duereason-action-"));
  const eventPath = join(dir, "event.json");
  writeFileSync(eventPath, JSON.stringify({ head_commit: { message: "Fix checkout rounding\n" } }));
  writeFileSync(join(dir, "output"), "");
  writeFileSync(join(dir, "summary"), "");
  env = {
    "INPUT_API-KEY": api.apiKey,
    INPUT_URL: api.url,
    INPUT_ACTION: "deployment",
    INPUT_REASON: "Release 2.4.0: fixes the checkout rounding bug customers reported.",
    INPUT_ENVIRONMENT: "production",
    "INPUT_TIMEOUT-MINUTES": "60",
    GITHUB_REPOSITORY: "acme/shop",
    GITHUB_SHA: SHA,
    GITHUB_REF: "refs/heads/main",
    GITHUB_EVENT_PATH: eventPath,
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_RUN_ID: "9001",
    GITHUB_WORKFLOW: "deploy",
    GITHUB_ACTOR: "octocat",
    GITHUB_OUTPUT: join(dir, "output"),
    GITHUB_STEP_SUMMARY: join(dir, "summary"),
  };
  log = [];
});

afterEach(() => api.close());

const start = (options: { signal?: AbortSignal } = {}) =>
  run(env, { ...options, log: (line) => log.push(line) });

/** GITHUB_OUTPUT is a sequence of `name<<DELIMITER\nvalue\nDELIMITER` blocks. */
function outputs(): Record<string, string> {
  const text = readFileSync(env.GITHUB_OUTPUT as string, "utf8");
  const result: Record<string, string> = {};
  for (const match of text.matchAll(/^([\w-]+)<<(\S+)\n([\s\S]*?)\n\2$/gm)) {
    result[match[1] as string] = match[3] as string;
  }
  return result;
}

const summary = () => readFileSync(env.GITHUB_STEP_SUMMARY as string, "utf8");
const errors = () => log.filter((line) => line.startsWith("::error"));

/** Files a request straight through the SDK, without running the action: for seeding fixtures
 *  (pending, rejected) that mode verify's lookup must never match. */
async function fileDirect(payload: JsonObject, overrides: Partial<ApprovalRequestInput> = {}) {
  const client = createClient({ apiKey: api.apiKey, baseUrl: api.url });
  return client.requestApproval(
    {
      action: "deployment",
      title: "Deploy shop to production",
      reason: "Release 2.4.0: routine production deploy.",
      payload,
      ...overrides,
    },
    { idempotencyKey: `direct:${Math.random()}` },
  );
}

/**
 * Request mode, approved with a real EdDSA grant signed by `key` (published in `api.jwks`), bound
 * to the request's actual payload hash so `verify` checks it the same way the real server's grant
 * would be checked. Resolves once the request step is done.
 */
async function approveWithGrant(
  overrides: Partial<Parameters<typeof signGrant>[2]> = {},
): Promise<{ request: Awaited<ReturnType<FakeApi["nextCreated"]>>; grant: string }> {
  const created = api.nextCreated();
  const exitCode = start();
  const request = await created;
  await api.nextPoll(request.id);
  const now = Math.floor(Date.now() / 1000);
  const grant = signGrant(key.privateKey, "gsk_test", {
    iss: api.url,
    org: "acme",
    sub: request.id,
    jti: `grt_${request.id}`,
    act: "deployment",
    ph: request.payloadHash,
    apv: ["usr_ana"],
    iat: now,
    exp: now + 3600,
    ...overrides,
  });
  api.update(request.id, {
    status: "approved",
    grant,
    responses: [
      {
        id: "rsp_1",
        step: 0,
        approver: { id: "usr_ana", name: "Ana Nowak" },
        verdict: "approved",
        comment: "Release notes checked.",
        at: new Date().toISOString(),
        evidence: [],
      },
    ],
  });
  expect(await exitCode).toBe(0);
  return { request, grant };
}

describe("DueReason approval action", () => {
  it("requests a deployment approval with the commit, waits, and outputs the grant", async () => {
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, {
      status: "approved",
      grant: "eyJ.grant.sig",
      responses: [
        {
          id: "rsp_1",
          step: 0,
          approver: { id: "usr_ana", name: "Ana Nowak" },
          verdict: "approved",
          comment: "Release notes checked.",
          at: new Date().toISOString(),
          evidence: [],
        },
      ],
    });

    expect(await exitCode).toBe(0);
    expect(request).toMatchObject({
      action: "deployment",
      title: "Deploy shop 1a2b3c4 to production",
      payload: {
        service: "shop",
        environment: "production",
        commit: SHA,
        changeSummary: "Fix checkout rounding",
      },
      agent: {
        name: "github-actions",
        repository: "acme/shop",
        ref: "refs/heads/main",
        runId: "9001",
        actor: "octocat",
      },
    });
    expect(request.context).toContainEqual({
      label: "Workflow run",
      url: "https://github.com/acme/shop/actions/runs/9001",
    });
    expect(outputs()).toEqual({
      "request-id": request.id,
      status: "approved",
      grant: "eyJ.grant.sig",
    });
    expect(summary()).toContain(`(${request.links.console})`);
    expect(summary()).toContain("Approved by Ana Nowak**: Release notes checked.");
    expect(errors()).toEqual([]);
  });

  it("fails the job with the approver's comment when rejected", async () => {
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, {
      status: "rejected",
      responses: [
        {
          id: "rsp_1",
          step: 0,
          approver: { id: "usr_jan", name: "Jan Kowalski" },
          verdict: "rejected",
          comment: "Not during the sale.\nWait for Monday.",
          at: new Date().toISOString(),
          evidence: [],
        },
      ],
    });

    expect(await exitCode).toBe(1);
    expect(outputs()).toEqual({ "request-id": request.id, status: "rejected" });
    // A newline in the comment must not end the workflow command early.
    expect(errors()).toEqual([
      expect.stringContaining("Rejected by Jan Kowalski: Not during the sale.%0AWait for Monday."),
    ]);
  });

  it("withdraws the request and fails when nobody decides in time", async () => {
    // Real time on purpose: the timeout is measured against real long-polls.
    await api.close();
    api = await startFakeApi({ maxWaitMs: 50 });
    env.INPUT_URL = api.url;
    env["INPUT_API-KEY"] = api.apiKey;
    env["INPUT_TIMEOUT-MINUTES"] = "0.005";

    expect(await start()).toBe(1);
    const [request] = [...api.approvals.values()];
    expect(request?.status).toBe("cancelled");
    expect(outputs()).toMatchObject({ status: "timeout" });
    expect(summary()).toContain("the request was withdrawn");
  });

  it("withdraws the request when the job is cancelled", async () => {
    const cancelled = new AbortController();
    const created = api.nextCreated();
    const exitCode = start({ signal: cancelled.signal });
    const request = await created;
    await api.nextPoll(request.id);
    cancelled.abort();

    expect(await exitCode).toBe(1);
    expect(api.approvals.get(request.id)?.status).toBe("cancelled");
  });

  it("sends a payload given as input exactly and reports a refusal", async () => {
    env.INPUT_ACTION = "rollback";
    env.INPUT_PAYLOAD = '{"service":"shop","to":"2.3.9"}';

    expect(await start()).toBe(1);
    const create = api.calls.find(
      (call) => call.method === "POST" && call.path === "/api/v1/approvals",
    );
    expect(create?.body).toMatchObject({
      action: "rollback",
      payload: { service: "shop", to: "2.3.9" },
    });
    expect(errors()).toEqual([expect.stringContaining("no_workflow")]);
    expect(outputs()).toEqual({});
  });

  it("refuses a payload that is not a JSON object before asking anyone", async () => {
    env.INPUT_PAYLOAD = "[1, 2]";
    expect(await start()).toBe(1);
    env.INPUT_PAYLOAD = "{service: shop}";
    expect(await start()).toBe(1);
    expect(api.calls).toEqual([]);
    expect(errors()).toHaveLength(2);
  });
});

describe("mandate-check", () => {
  it("files exactly one request under a covering mandate: approved instantly, grant + mandate-id set, no cancel", async () => {
    api.checkMandate = (checked) => {
      expect(checked).toMatchObject({ actionKey: "deployment" });
      expect(checked.agent).toMatchObject({ name: "github-actions", repository: "acme/shop" });
      return {
        covered: true,
        mandate: fakeMandate(),
        remaining: { cumulative: null, count: { period: "day", max: 10, used: 3, remaining: 7 } },
        reasons: [],
      };
    };
    api.autoApprove = () => ({
      status: "approved",
      grant: "eyJ.grant.sig",
      responses: [
        {
          id: "rsp_1",
          step: 0,
          approver: { id: "usr_system", name: "Mandate mdt_1" },
          verdict: "approved",
          comment: "Auto-approved under mandate mdt_1.",
          at: new Date().toISOString(),
          evidence: [],
        },
      ],
    });

    expect(await start()).toBe(0);
    const [request] = [...api.approvals.values()];
    expect(request).toBeDefined();
    expect(outputs()).toEqual({
      "request-id": request?.id,
      status: "approved",
      grant: "eyJ.grant.sig",
      "mandate-id": "mdt_1",
    });
    expect(summary()).toContain("mdt_1");
    expect(errors()).toEqual([]);

    // Exactly one POST /api/v1/approvals: the mandate path still files a real request, with the
    // same payload and agent as any other, so the mandate's limits and the ledger see it.
    const creates = api.calls.filter(
      (call) => call.method === "POST" && call.path === "/api/v1/approvals",
    );
    expect(creates).toHaveLength(1);
    expect(creates[0]?.body).toMatchObject({
      action: "deployment",
      payload: { service: "shop", environment: "production", commit: SHA },
      agent: { name: "github-actions", repository: "acme/shop" },
    });
    // Nothing was ever pending, so there is nothing to withdraw.
    expect(api.calls.some((call) => call.method === "POST" && call.path.endsWith("/cancel"))).toBe(
      false,
    );
  });

  it("waits normally when the create answers pending despite a covering pre-check (budget changed in between)", async () => {
    api.checkMandate = () => ({
      covered: true,
      mandate: fakeMandate(),
      remaining: { cumulative: null, count: { period: "day", max: 10, used: 10, remaining: 0 } },
      reasons: [],
    });
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, {
      status: "approved",
      grant: "eyJ.grant.sig",
      responses: [
        {
          id: "rsp_1",
          step: 0,
          approver: { id: "usr_ana", name: "Ana Nowak" },
          verdict: "approved",
          comment: "",
          at: new Date().toISOString(),
          evidence: [],
        },
      ],
    });

    expect(await exitCode).toBe(0);
    expect(outputs()).toEqual({
      "request-id": request.id,
      status: "approved",
      grant: "eyJ.grant.sig",
    });
    expect(summary()).not.toContain("mandate");
    expect(log.some((line) => line.startsWith("::notice") && line.includes("mdt_1"))).toBe(true);
  });

  it("falls through to the normal wait-for-approval flow when not covered", async () => {
    api.checkMandate = () => ({
      covered: false,
      mandate: null,
      remaining: null,
      reasons: ["No mandate."],
    });
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, {
      status: "approved",
      grant: "eyJ.grant.sig",
      responses: [
        {
          id: "rsp_1",
          step: 0,
          approver: { id: "usr_ana", name: "Ana Nowak" },
          verdict: "approved",
          comment: "",
          at: new Date().toISOString(),
          evidence: [],
        },
      ],
    });

    expect(await exitCode).toBe(0);
    expect(outputs()).toEqual({
      "request-id": request.id,
      status: "approved",
      grant: "eyJ.grant.sig",
    });
    expect(
      api.calls.some((call) => call.path === "/api/v1/mandates/check" && call.method === "POST"),
    ).toBe(true);
  });

  it("skips the check entirely when mandate-check is false, even if a mandate would cover it", async () => {
    env["INPUT_MANDATE-CHECK"] = "false";
    api.checkMandate = () => ({
      covered: true,
      mandate: fakeMandate(),
      remaining: null,
      reasons: [],
    });

    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, { status: "approved", grant: "eyJ.grant.sig", responses: [] });

    expect(await exitCode).toBe(0);
    expect(
      api.calls.some((call) => call.path === "/api/v1/mandates/check" && call.method === "POST"),
    ).toBe(false);
  });

  it("downgrades an insufficient_scope mandate pre-check failure to a notice", async () => {
    api.failNext("POST /api/v1/mandates/check", { status: 403, code: "insufficient_scope" });
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, { status: "approved", grant: "eyJ.grant.sig", responses: [] });

    expect(await exitCode).toBe(0);
    expect(outputs()).toEqual({
      "request-id": request.id,
      status: "approved",
      grant: "eyJ.grant.sig",
    });
    expect(log.some((line) => line.startsWith("::notice") && line.includes("mandate:read"))).toBe(
      true,
    );
    expect(log.some((line) => line.startsWith("::warning"))).toBe(false);
  });

  it("still files the request normally and warns when the mandate pre-check fails for another reason", async () => {
    api.failNext("POST /api/v1/mandates/check", { status: 401, code: "unauthorized" });
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, { status: "approved", grant: "eyJ.grant.sig", responses: [] });

    expect(await exitCode).toBe(0);
    expect(outputs()).toEqual({
      "request-id": request.id,
      status: "approved",
      grant: "eyJ.grant.sig",
    });
    expect(log.some((line) => line.startsWith("::warning") && line.includes("unauthorized"))).toBe(
      true,
    );
  });

  it("a mandate-approved run's outputs work for a follow-up mode: report step", async () => {
    api.checkMandate = () => ({
      covered: true,
      mandate: fakeMandate(),
      remaining: null,
      reasons: [],
    });
    api.autoApprove = () => ({ status: "approved", grant: "eyJ.grant.sig", responses: [] });

    expect(await start()).toBe(0);
    const [request] = [...api.approvals.values()];
    const requestOutputs = outputs();
    expect(requestOutputs["mandate-id"]).toBe("mdt_1");

    log = [];
    env.INPUT_MODE = "report";
    env.INPUT_GRANT = requestOutputs.grant as string;
    env["INPUT_REQUEST-ID"] = requestOutputs["request-id"] as string;
    env.INPUT_OUTCOME = "succeeded";

    expect(await start()).toBe(0);
    expect(api.approvals.get(request?.id ?? "")?.execution).toMatchObject({
      outcome: "succeeded",
    });
    expect(errors()).toEqual([]);
  });
});

describe("mode verify", () => {
  it("passes for the grant of an approved request and sets request-id from its claims", async () => {
    const { request, grant } = await approveWithGrant();
    log = [];
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";
    env.INPUT_GRANT = grant;

    expect(await start()).toBe(0);
    expect(outputs()["request-id"]).toBe(request.id);
    expect(summary()).toContain(`verified`);
    expect(errors()).toEqual([]);
  });

  it("fails with payload_mismatch when the payload input differs from what was approved", async () => {
    const { grant } = await approveWithGrant();
    log = [];
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";
    env.INPUT_GRANT = grant;
    env.INPUT_PAYLOAD = JSON.stringify({
      service: "other",
      environment: "production",
      commit: SHA,
    });

    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("payload_mismatch")]);
  });

  it("looks up the newest approved request by action + payload when the grant input is missing", async () => {
    const { request } = await approveWithGrant();
    log = [];
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";

    expect(await start()).toBe(0);
    expect(outputs()["request-id"]).toBe(request.id);
    expect(summary()).toContain("verified");
    expect(errors()).toEqual([]);
    expect(
      api.calls.some(
        (call) =>
          call.method === "GET" &&
          call.path === "/api/v1/approvals" &&
          call.query.get("status") === "approved" &&
          call.query.get("action") === "deployment" &&
          call.query.get("payloadHash") === request.payloadHash,
      ),
    ).toBe(true);
  });

  it("fails clearly when the organization input is missing", async () => {
    const { grant } = await approveWithGrant();
    log = [];
    env.INPUT_MODE = "verify";
    env.INPUT_GRANT = grant;

    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("organization")]);
  });
});

describe("mode verify: lookup (no grant input)", () => {
  it("fails without filing anything when no approved request matches this payload", async () => {
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";

    expect(await start()).toBe(1);
    expect(errors()).toEqual([
      expect.stringContaining('No approved request found for action "deployment"'),
    ]);
    expect(api.calls.some((call) => call.method === "POST")).toBe(false);
  });

  it("fails on a pending request for the exact same payload: it is not approved yet", async () => {
    const pending = await fileDirect({
      service: "shop",
      environment: "production",
      commit: SHA,
      changeSummary: "Fix checkout rounding",
    });
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";
    env.INPUT_PAYLOAD = JSON.stringify(pending.payload);

    expect(await start()).toBe(1);
    expect(errors()).toEqual([
      expect.stringContaining('No approved request found for action "deployment"'),
    ]);
  });

  it("fails on a rejected request for the exact same payload", async () => {
    const request = await fileDirect({
      service: "shop",
      environment: "production",
      commit: SHA,
      changeSummary: "Fix checkout rounding",
    });
    api.update(request.id, { status: "rejected" });
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";
    env.INPUT_PAYLOAD = JSON.stringify(request.payload);

    expect(await start()).toBe(1);
    expect(errors()).toEqual([
      expect.stringContaining('No approved request found for action "deployment"'),
    ]);
  });

  it("fails when the only matching approved request's grant has already expired", async () => {
    const now = Math.floor(Date.now() / 1000);
    await approveWithGrant({ iat: now - 7200, exp: now - 1 });
    log = [];
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";

    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("expired")]);
  });

  it("with request-if-missing: files a request and fails, waiting for approval", async () => {
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";
    env["INPUT_REQUEST-IF-MISSING"] = "true";
    const created = api.nextCreated();

    const exitCode = await start();
    const request = await created;

    expect(exitCode).toBe(1);
    expect(outputs()["request-id"]).toBe(request.id);
    expect(errors()).toEqual([expect.stringContaining(`filed ${request.id}`)]);
    expect(request.status).toBe("pending");
  });

  it("request-if-missing requires a reason", async () => {
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";
    env["INPUT_REQUEST-IF-MISSING"] = "true";
    env.INPUT_REASON = "";

    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("reason")]);
    expect(api.calls.some((call) => call.method === "POST")).toBe(false);
  });

  it("a second verify after approval of the filed request passes", async () => {
    env.INPUT_MODE = "verify";
    env.INPUT_ORGANIZATION = "acme";
    env["INPUT_REQUEST-IF-MISSING"] = "true";
    const created = api.nextCreated();
    await start();
    const request = await created;
    const now = Math.floor(Date.now() / 1000);
    const grant = signGrant(key.privateKey, "gsk_test", {
      iss: api.url,
      org: "acme",
      sub: request.id,
      jti: `grt_${request.id}`,
      act: "deployment",
      ph: request.payloadHash,
      apv: ["usr_ana"],
      iat: now,
      exp: now + 3600,
    });
    api.update(request.id, { status: "approved", grant });

    log = [];
    expect(await start()).toBe(0);
    expect(outputs()["request-id"]).toBe(request.id);
  });
});

describe("mode report", () => {
  it("records the outcome on the fake", async () => {
    const { request, grant } = await approveWithGrant();
    log = [];
    env.INPUT_MODE = "report";
    env.INPUT_GRANT = grant;
    env["INPUT_REQUEST-ID"] = request.id;
    env.INPUT_OUTCOME = "succeeded";

    expect(await start()).toBe(0);
    expect(api.approvals.get(request.id)?.execution).toMatchObject({ outcome: "succeeded" });
    expect(summary()).toContain("reported as succeeded");
    expect(errors()).toEqual([]);
  });

  it("records a failure with its detail", async () => {
    const { request, grant } = await approveWithGrant();
    log = [];
    env.INPUT_MODE = "report";
    env.INPUT_GRANT = grant;
    env["INPUT_REQUEST-ID"] = request.id;
    env.INPUT_OUTCOME = "failed";
    env.INPUT_DETAIL = "deploy script exited 1";

    expect(await start()).toBe(0);
    expect(api.approvals.get(request.id)?.execution).toMatchObject({
      outcome: "failed",
      detail: "deploy script exited 1",
    });
  });

  it("fails with already_executed on a genuinely new report for an already-reported run (a grant is single-use)", async () => {
    const { request, grant } = await approveWithGrant();
    env.INPUT_MODE = "report";
    env.INPUT_GRANT = grant;
    env["INPUT_REQUEST-ID"] = request.id;
    env.INPUT_OUTCOME = "succeeded";
    expect(await start()).toBe(0);

    // A different GITHUB_RUN_ID means a distinct idempotency key, so this is a real second
    // report (e.g. a stray duplicate workflow run), not a retry of the same step.
    env.GITHUB_RUN_ID = "9002";
    log = [];
    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("already_executed")]);
  });

  it("replays the first response on a re-run of the same report step instead of already_executed", async () => {
    const { request, grant } = await approveWithGrant();
    env.INPUT_MODE = "report";
    env.INPUT_GRANT = grant;
    env["INPUT_REQUEST-ID"] = request.id;
    env.INPUT_OUTCOME = "succeeded";
    expect(await start()).toBe(0);

    // Same GITHUB_RUN_ID (and everything else): a "re-run failed jobs" of the exact same step.
    log = [];
    expect(await start()).toBe(0);
    expect(errors()).toEqual([]);
    expect(summary()).toContain("reported as succeeded");
    expect(api.approvals.get(request.id)?.execution).toMatchObject({ outcome: "succeeded" });
  });

  it("uses a distinct idempotency key from a request/verify step in the same run", async () => {
    const { request, grant } = await approveWithGrant();
    const reportCreates = () =>
      api.calls.filter(
        (call) =>
          call.method === "POST" && call.path === `/api/v1/approvals/${request.id}/executions`,
      );
    env.INPUT_MODE = "report";
    env.INPUT_GRANT = grant;
    env["INPUT_REQUEST-ID"] = request.id;
    env.INPUT_OUTCOME = "succeeded";
    expect(await start()).toBe(0);

    const reportKey = reportCreates()[0]?.headers["idempotency-key"];
    const requestKey = api.calls.find(
      (call) => call.method === "POST" && call.path === "/api/v1/approvals",
    )?.headers["idempotency-key"];
    expect(reportKey).toBeTruthy();
    expect(reportKey).not.toBe(requestKey);
  });

  it("fails clearly when the request-id or grant input is missing", async () => {
    env.INPUT_MODE = "report";
    env.INPUT_OUTCOME = "succeeded";
    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("request-id")]);

    log = [];
    env["INPUT_REQUEST-ID"] = "apr_1";
    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("grant")]);
    expect(api.calls).toEqual([]);
  });

  it("fails clearly on an invalid outcome, without reporting anything", async () => {
    const { request, grant } = await approveWithGrant();
    log = [];
    const callsBefore = api.calls.length;
    env.INPUT_MODE = "report";
    env.INPUT_GRANT = grant;
    env["INPUT_REQUEST-ID"] = request.id;
    env.INPUT_OUTCOME = "done";

    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("outcome")]);
    expect(api.calls.length).toBe(callsBefore);
    expect(api.approvals.get(request.id)?.execution).toBeNull();
  });
});

describe("idempotency key on the approval request", () => {
  /** The Idempotency-Key header sent on the POST /approvals call. */
  function requestedIdempotencyKey(): string | undefined {
    const creates = api.calls.filter(
      (call) => call.method === "POST" && call.path === "/api/v1/approvals",
    );
    const header = creates[creates.length - 1]?.headers["idempotency-key"];
    return Array.isArray(header) ? header[0] : header;
  }

  it("replays the same key across two calls with an identical env (a job re-run)", async () => {
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, { status: "approved", grant: "eyJ.grant.sig", responses: [] });
    expect(await exitCode).toBe(0);
    const first = requestedIdempotencyKey();
    expect(first).toBeTruthy();

    await api.close();
    api = await startFakeApi();
    api.jwks.keys.push(key.jwk);
    env.INPUT_URL = api.url;
    env["INPUT_API-KEY"] = api.apiKey;
    log = [];
    const created2 = api.nextCreated();
    const exitCode2 = start();
    const request2 = await created2;
    await api.nextPoll(request2.id);
    api.update(request2.id, { status: "approved", grant: "eyJ.grant.sig", responses: [] });
    expect(await exitCode2).toBe(0);

    expect(requestedIdempotencyKey()).toBe(first);
  });

  it("uses a distinct key for a different action in the same run", async () => {
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, { status: "approved", grant: "eyJ.grant.sig", responses: [] });
    expect(await exitCode).toBe(0);
    const first = requestedIdempotencyKey();

    env.INPUT_ACTION = "rollback";
    env.INPUT_PAYLOAD = '{"service":"shop","to":"2.3.9"}';
    log = [];
    expect(await start()).toBe(1); // no_workflow for `rollback`, but the request was still posted
    expect(requestedIdempotencyKey()).not.toBe(first);
  });

  it("uses a distinct key for a different GITHUB_RUN_ID (a genuinely new workflow run)", async () => {
    const created = api.nextCreated();
    const exitCode = start();
    const request = await created;
    await api.nextPoll(request.id);
    api.update(request.id, { status: "approved", grant: "eyJ.grant.sig", responses: [] });
    expect(await exitCode).toBe(0);
    const first = requestedIdempotencyKey();

    env.GITHUB_RUN_ID = "9002";
    log = [];
    const created2 = api.nextCreated();
    const exitCode2 = start();
    const request2 = await created2;
    await api.nextPoll(request2.id);
    api.update(request2.id, { status: "approved", grant: "eyJ.grant.sig", responses: [] });
    expect(await exitCode2).toBe(0);

    expect(requestedIdempotencyKey()).not.toBe(first);
  });
});

describe("mode (unknown)", () => {
  it("fails the step instead of silently doing nothing", async () => {
    env.INPUT_MODE = "rollout";
    expect(await start()).toBe(1);
    expect(errors()).toEqual([expect.stringContaining("mode")]);
    expect(api.calls).toEqual([]);
  });
});
