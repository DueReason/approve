import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import {
  type ApprovalRequest,
  createClient,
  DueReasonApiError,
  type FindApprovedGrantResult,
  findApprovedGrant,
  type GrantClaims,
  GrantVerificationError,
  type JsonObject,
  type MandateCheckResult,
} from "@duereason/sdk";

/**
 * The action, as a function of the runner's environment: inputs arrive as
 * INPUT_<NAME> variables, outputs and the job summary go to the files named by
 * GITHUB_OUTPUT and GITHUB_STEP_SUMMARY. Resolves with the exit code.
 *
 * Three modes, dispatched on the `mode` input:
 * - request (default): ask for approval and wait for the grant.
 * - verify: check a grant against a payload before running it, offline.
 * - report: record how an approved action that already ran turned out.
 */

export interface RunOptions {
  fetch?: typeof fetch;
  /** Aborted when the job is cancelled: the request is withdrawn. */
  signal?: AbortSignal;
  log?: (line: string) => void;
}

type Outcome = ApprovalRequest["status"] | "timeout";
type Fail = (message: string) => number;
type Input = (name: string) => string;

export async function run(
  env: Record<string, string | undefined>,
  options: RunOptions = {},
): Promise<number> {
  const log = options.log ?? ((line: string) => console.log(line));
  const input: Input = (name) => (env[`INPUT_${name.toUpperCase()}`] ?? "").trim();
  const fail: Fail = (message) => {
    log(`::error title=DueReason::${escapeCommand(message)}`);
    return 1;
  };

  const apiKey = input("api-key");
  if (!apiKey)
    return fail(
      "Set the api-key input from a secret: an API key with the approval:request and approval:read scopes.",
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

/** Ask for approval and wait for the grant. The single original behaviour, unchanged. */
async function runRequest(
  env: Record<string, string | undefined>,
  input: Input,
  apiKey: string,
  fail: Fail,
  log: (line: string) => void,
  options: RunOptions,
): Promise<number> {
  const reason = input("reason");
  if (!reason) return fail("Set the reason input: why this should happen. Approvers decide on it.");
  const timeoutMinutes = Number(input("timeout-minutes") || "60");
  if (!Number.isFinite(timeoutMinutes) || timeoutMinutes <= 0 || timeoutMinutes > 10_080) {
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
    baseUrl: input("url") || undefined,
    fetch: options.fetch,
  });

  const agent = {
    name: "github-actions",
    repository,
    ref: env.GITHUB_REF,
    workflow: env.GITHUB_WORKFLOW,
    runId: env.GITHUB_RUN_ID,
    actor: env.GITHUB_ACTOR,
  };

  // A mandate ("approve up to N deploys/day, automatically") can already authorize
  // exactly this request. Checked first, same as MCP's check_mandate tool, but only to
  // tell the operator what is about to happen: the request is always filed below, so the
  // mandate's limits count it and a receipt exists. The server auto-approves instantly
  // under a covering mandate (POST /approvals already returns status "approved" + a grant
  // in that case) -- this pre-check never substitutes for filing the request.
  let mandateCoverage: { id: string } | null = null;
  if (input("mandate-check") !== "false") {
    try {
      const mandate = await client.checkMandate({ actionKey: action, payload, agent });
      if (mandate.covered && mandate.mandate) {
        mandateCoverage = { id: mandate.mandate.id };
        log(
          `Mandate ${mandate.mandate.id} covers this; filing the request, it approves instantly and uses 1 of ${mandateRemaining(mandate.remaining)} remaining.`,
        );
      }
    } catch (error) {
      // Advisory only: a broken check must never stop the normal request-and-wait flow.
      // insufficient_scope is expected and benign for a key that never opted into
      // mandate:read (e.g. the quickstart default before 2026-11-09, or mandate-check
      // deliberately left on with a narrower key): a notice, not a warning.
      if (error instanceof DueReasonApiError && error.code === "insufficient_scope") {
        log(
          `::notice title=DueReason::Skipping the mandate pre-check: this API key lacks the optional mandate:read scope. Add it to see mandate coverage logged in advance, or set mandate-check: "false" to silence this notice.`,
        );
      } else {
        log(
          `::warning title=DueReason::Checking mandate coverage failed, requesting approval as usual: ${escapeCommand(describe(error))}`,
        );
      }
    }
  }

  /** Withdraw a request; if approvers decided it in the meantime, their decision stands. */
  const withdraw = async (pending: ApprovalRequest): Promise<ApprovalRequest> => {
    try {
      return await client.cancelApproval(pending.id);
    } catch (error) {
      if (error instanceof DueReasonApiError && error.code === "not_pending") {
        return client.getApproval(pending.id);
      }
      throw error;
    }
  };

  let request: ApprovalRequest;
  try {
    request = await client.requestApproval(
      {
        action,
        title,
        reason,
        payload,
        agent,
        context: repository
          ? [
              { label: "Workflow run", url: runUrl },
              ...(sha
                ? [
                    {
                      label: "Commit",
                      url: `${env.GITHUB_SERVER_URL ?? "https://github.com"}/${repository}/commit/${sha}`,
                    },
                  ]
                : []),
            ]
          : undefined,
        // Expires when this job stops waiting (the API minimum is 60 s).
        expiresInSeconds: Math.min(604_800, Math.max(60, Math.ceil(timeoutMinutes * 60))),
      },
      {
        // Stable across "re-run failed jobs" (same GITHUB_RUN_ID, only run_attempt changes), so a
        // retried step replays the first request instead of opening a duplicate one. `action` keeps
        // two DueReason steps in the same run (e.g. staging + production) from colliding.
        idempotencyKey: `gha:${repository}:${env.GITHUB_RUN_ID}:${action}`,
      },
    );
  } catch (error) {
    return fail(`Requesting approval failed: ${describe(error)}`);
  }
  setOutput(env, "request-id", request.id);
  log(`Approval requested: ${request.links.console}`);

  // The server consumes a covering mandate inside the same create call (matchAndConsumeMandate,
  // called from openApprovalRequest): a request that was already decided the instant it was filed
  // (status is not "pending" here, before any wait) is what "approved instantly under this
  // mandate" means. If the pre-check said covered but the request is still pending, its budget
  // changed in the time between the check and the create (another run used it up, or it expired):
  // that is not a mandate approval, so wait like any other request and leave mandate-id unset.
  let mandateApprovedId: string | null = null;
  if (mandateCoverage) {
    if (request.status !== "pending") {
      mandateApprovedId = mandateCoverage.id;
    } else {
      log(
        `::notice title=DueReason::Mandate ${mandateCoverage.id} looked like it covered this, but the request is still pending (its budget changed meanwhile); waiting for a decision as usual.`,
      );
    }
  }

  let outcome: Outcome;
  try {
    // A request already decided (the mandate path) answers at once, whatever the wait.
    request = await client.waitForApproval(request.id, {
      timeoutMs: timeoutMinutes * 60_000,
      signal: options.signal,
    });
    outcome = request.status;
    if (outcome === "pending") {
      // Timed out: nobody should approve a job that stopped waiting.
      request = await withdraw(request);
      outcome = request.status === "cancelled" ? "timeout" : request.status;
    }
  } catch (error) {
    if (options.signal?.aborted) {
      await withdraw(request).catch(() => undefined);
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
    outcome === "approved" ? mandateApprovedId : null,
  );

  const rejection = request.responses.find((response) => response.verdict === "rejected");
  switch (outcome) {
    case "approved":
      log(`Approved: ${request.links.console}`);
      return 0;
    case "rejected":
      return fail(
        `Rejected by ${rejection?.approver.name ?? "an approver"}: ${rejection?.comment ?? ""} (${request.links.console})`,
      );
    case "timeout":
      return fail(`No decision within ${timeoutMinutes} minutes; the request was withdrawn.`);
    default:
      return fail(`The approval request was ${outcome}. (${request.links.console})`);
  }
}

/**
 * mode verify: check that an approved grant exists for this exact payload, without creating a
 * request or consuming anything. With `grant` set, checks it offline directly (the original
 * behaviour: a request step in the same job handed it over). Without it, looks up the newest
 * APPROVED request for this action + payload via the API and verifies its grant the same way --
 * the target-side check a required GitHub status check or an independent deploy step needs, since
 * neither ever received a `grant` output themselves. `request-if-missing` files a request instead
 * of just failing when none is found yet.
 */
async function runVerify(
  env: Record<string, string | undefined>,
  input: Input,
  apiKey: string,
  fail: Fail,
  log: (line: string) => void,
  options: RunOptions,
): Promise<number> {
  const organization = input("organization");
  if (!organization) return fail("Set the organization input: your DueReason organization slug.");
  const resolved = resolvePayload(input, env);
  if ("error" in resolved) return fail(resolved.error);
  const { payload } = resolved;
  const action = input("action") || "deployment";

  const client = createClient({
    apiKey,
    baseUrl: input("url") || undefined,
    fetch: options.fetch,
  });

  const grant = input("grant");
  if (grant) {
    let claims: GrantClaims;
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

  let found: FindApprovedGrantResult | null;
  try {
    found = await findApprovedGrant(client, { action, payload, organization });
  } catch (error) {
    if (error instanceof GrantVerificationError) {
      return fail(
        `An approved request exists for this payload, but its grant does not authorize it: ${error.reason}: ${error.message}. File a new request and get it approved again.`,
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
        "Set the reason input: request-if-missing files a request when none is approved yet, and DueReason requires a reason.",
      );
    }
    const environment = input("environment") || "production";
    const repository = env.GITHUB_REPOSITORY ?? "";
    const title = input("title") || defaultTitle(env, action, environment);
    const runUrl = `${env.GITHUB_SERVER_URL ?? "https://github.com"}/${repository}/actions/runs/${env.GITHUB_RUN_ID}`;
    let request: ApprovalRequest;
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
            actor: env.GITHUB_ACTOR,
          },
          context: repository ? [{ label: "Workflow run", url: runUrl }] : undefined,
        },
        // Distinct from mode request's key (suffixed `:verify`): the two can run in the same
        // workflow run for different purposes and must never collide or replay each other.
        { idempotencyKey: `gha:${repository}:${env.GITHUB_RUN_ID}:${action}:verify` },
      );
    } catch (error) {
      return fail(`Filing the approval request failed: ${describe(error)}`);
    }
    setOutput(env, "request-id", request.id);
    summarizeOneLine(
      env,
      `No approved request yet; filed \`${request.id}\`, waiting for approval.`,
    );
    return fail(
      `No approved request for this payload yet; filed ${request.id} and it is waiting for approval: ${request.links.console}. Re-run this check once it is approved.`,
    );
  }

  return fail(
    `No approved request found for action "${action}" with this exact payload. File one in DueReason and get it approved, then re-run this check: ${consoleBase}/app/approvals`,
  );
}

/**
 * Record how an approved action that already ran turned out. A grant is
 * single-use: the server refuses a second report with already_executed.
 */
async function runReport(
  env: Record<string, string | undefined>,
  input: Input,
  apiKey: string,
  fail: Fail,
  log: (line: string) => void,
  options: RunOptions,
): Promise<number> {
  const requestId = input("request-id");
  if (!requestId)
    return fail("Set the request-id input: the request-id output from the request step.");
  const grant = input("grant");
  if (!grant) return fail("Set the grant input: the grant output from the request step.");
  const outcome = input("outcome");
  if (outcome !== "succeeded" && outcome !== "failed") {
    return fail('Set the outcome input to "succeeded" or "failed".');
  }
  const detail = input("detail") || undefined;
  const action = input("action") || "deployment";
  const repository = env.GITHUB_REPOSITORY ?? "";

  const client = createClient({
    apiKey,
    baseUrl: input("url") || undefined,
    fetch: options.fetch,
  });

  try {
    await client.reportExecution(
      requestId,
      { grant, outcome, detail },
      // Stable across "re-run failed jobs" (same GITHUB_RUN_ID, only run_attempt changes), so a
      // retried report step replays the first answer instead of hitting a fresh already_executed.
      // `action` keeps two report steps in the same run (e.g. staging + production) from colliding.
      { idempotencyKey: `gha:${repository}:${env.GITHUB_RUN_ID}:${action}:report` },
    );
  } catch (error) {
    if (error instanceof DueReasonApiError && error.code === "already_executed") {
      return fail(
        `already_executed: ${requestId} was already reported executed; a grant is single-use. This step ran twice.`,
      );
    }
    return fail(`Reporting the execution failed: ${describe(error)}`);
  }
  summarizeOneLine(env, `Execution of \`${requestId}\` reported as ${outcome}.`);
  log(`Execution reported: ${outcome}.`);
  return 0;
}

/** Default title for a request step, or a request-if-missing verify step: shared by both. */
function defaultTitle(
  env: Record<string, string | undefined>,
  action: string,
  environment: string,
): string {
  const repository = env.GITHUB_REPOSITORY ?? "";
  const service = repository.split("/").pop() || repository;
  const sha = env.GITHUB_SHA ?? "";
  return action === "deployment"
    ? `Deploy ${service} ${sha.slice(0, 7)} to ${environment}`
    : `${action} from ${env.GITHUB_WORKFLOW ?? "a workflow"} in ${repository}`;
}

/** The payload input, parsed, or the default deployment payload. Shared by request and verify. */
function resolvePayload(
  input: Input,
  env: Record<string, string | undefined>,
): { payload: JsonObject } | { error: string } {
  const environment = input("environment") || "production";
  const repository = env.GITHUB_REPOSITORY ?? "";
  const service = repository.split("/").pop() || repository;
  const sha = env.GITHUB_SHA ?? "";
  if (input("payload")) {
    let payload: unknown;
    try {
      payload = JSON.parse(input("payload"));
    } catch {
      return { error: "The payload input is not valid JSON." };
    }
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
      return { error: "The payload input must be a JSON object." };
    }
    return { payload: payload as JsonObject };
  }
  // The fields of the deployment action the installable template creates; the ref goes in `agent`.
  return {
    payload: {
      service,
      environment,
      commit: sha,
      changeSummary: commitMessage(env)?.slice(0, 2000),
    },
  };
}

/** The commit message the push carried, else what git knows about the commit. */
function commitMessage(env: Record<string, string | undefined>): string | undefined {
  if (env.GITHUB_EVENT_PATH) {
    try {
      const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8"));
      const message: unknown = event.head_commit?.message ?? event.pull_request?.title;
      if (typeof message === "string" && message.trim()) return message.trim();
    } catch {
      // No readable event payload: fall through to git.
    }
  }
  if (!env.GITHUB_WORKSPACE || !env.GITHUB_SHA) return undefined;
  try {
    const message = execFileSync("git", ["log", "-1", "--format=%B", env.GITHUB_SHA], {
      cwd: env.GITHUB_WORKSPACE,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return message || undefined;
  } catch {
    return undefined;
  }
}

function setOutput(env: Record<string, string | undefined>, name: string, value: string) {
  if (!env.GITHUB_OUTPUT) return;
  const delimiter = `duereason_${randomUUID()}`;
  appendFileSync(env.GITHUB_OUTPUT, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}

function summarize(
  env: Record<string, string | undefined>,
  request: ApprovalRequest,
  outcome: Outcome,
  timeoutMinutes: number,
  mandateId: string | null,
) {
  if (!env.GITHUB_STEP_SUMMARY) return;
  const lines = [
    `### DueReason approval: ${outcome}`,
    "",
    `- **Request:** [${markdown(request.title)}](${request.links.console})`,
    `- **Action:** ${markdown(request.action)}${request.workflow.name ? `, workflow ${markdown(request.workflow.name)} v${request.workflow.version}` : ""}`,
    ...(mandateId
      ? [
          `- **Approved under mandate** \`${mandateId}\`: a request was filed and immediately decided, so it counts against the mandate's limit and has a receipt like any other.`,
        ]
      : []),
    ...request.responses.map(
      (response) =>
        `- **${response.verdict === "approved" ? "Approved" : "Rejected"} by ${markdown(response.approver.name)}**${response.comment ? `: ${markdown(response.comment)}` : ""}`,
    ),
    `- **Payload hash:** \`${request.payloadHash}\``,
    outcome === "timeout"
      ? `\nNo decision within ${timeoutMinutes} minutes; the request was withdrawn.`
      : "",
    "",
  ];
  appendFileSync(env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}\n`);
}

/** The one-line summary verify and report write. */
function summarizeOneLine(env: Record<string, string | undefined>, line: string) {
  if (!env.GITHUB_STEP_SUMMARY) return;
  appendFileSync(env.GITHUB_STEP_SUMMARY, `DueReason: ${line}\n`);
}

/** How much budget `checkMandate`'s pre-check reported left on the mandate, for the log line. */
function mandateRemaining(remaining: MandateCheckResult["remaining"]): string {
  const left = remaining?.count?.remaining ?? remaining?.cumulative?.remaining;
  return left === undefined ? "an unknown number of" : String(left);
}

/** Approver and agent text is shown as text, never as markup. */
function markdown(text: string): string {
  return text.replace(/[\\`*_{}[\]()<>#+!|~]/g, "\\$&").replace(/\s*\n\s*/g, " ");
}

/** Workflow command data: %, CR and LF would end or forge the command. */
function escapeCommand(text: string): string {
  return text.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}

function describe(error: unknown): string {
  if (error instanceof DueReasonApiError) return `${error.code}: ${error.message}`;
  if (!(error instanceof Error)) return String(error);
  // fetch reports "fetch failed" and keeps the reason (ECONNREFUSED, a TLS error) in `cause`.
  return error.cause instanceof Error ? `${error.message} (${error.cause.message})` : error.message;
}
