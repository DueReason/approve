# DueReason approval (GitHub Action)

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Holds a job until the people your organization configured in DueReason approve it, then hands the
signed grant to the next step. The job fails on rejection, expiry, cancellation or timeout, and a
request the job stopped waiting for is withdrawn, so nobody approves a deploy that will never run.

```yaml
- id: approval
  uses: duereason/approve@v1
  with:
    api-key: *** secrets.DUEREASON_API_KEY }}
    reason: "Release ${{ github.sha }} from ${{ github.ref_name }}."
    payload: '{"service":"shop","environment":"production","commit":"${{ github.sha }}"}'
    timeout-minutes: 120
```

A full workflow, including verifying the grant and reporting the outcome, is in
[`examples/deploy-gate.yml`](./examples/deploy-gate.yml).

## Usage

<!-- availability:start -->
**`uses: duereason/approve@v1` resolves once this repository is pushed under that name and
tagged `v1` (or `action-v1`) - until then, pin `uses:` to a commit SHA on this repository
instead of `@v1`.** [VERIFY the final org/repo name and tag convention with Leszek before
relying on `@v1` in a workflow.]
<!-- availability:end -->

Create an API key in DueReason with the `approval:request`, `approval:read` and `mandate:read`
scopes and store it as the `DUEREASON_API_KEY` secret (the action's `mandate-check` pre-check
defaults to on and needs `mandate:read`; see below to skip it and drop that scope). Gating a
production deploy:

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      PAYLOAD: '{"service":"shop","environment":"production","commit":"${{ github.sha }}"}'
    steps:
      - uses: actions/checkout@v7
      - id: approval
        uses: duereason/approve@v1
        with:
          api-key: *** secrets.DUEREASON_API_KEY }}
          reason: "Release ${{ github.sha }} from ${{ github.ref_name }}: ${{ github.event.head_commit.message }}"
          payload: ${{ env.PAYLOAD }}
          timeout-minutes: 120
      - name: Verify the grant covers exactly this payload
        uses: duereason/approve@v1
        with:
          mode: verify
          api-key: *** secrets.DUEREASON_API_KEY }}
          organization: acme
          payload: ${{ env.PAYLOAD }}
          grant: ${{ steps.approval.outputs.grant }}
      - uses: actions/setup-node@v7
        with:
          node-version: 24
      - run: npm ci
      - run: npm run deploy
      - name: Report the execution
        if: always()
        uses: duereason/approve@v1
        with:
          mode: report
          api-key: *** secrets.DUEREASON_API_KEY }}
          request-id: ${{ steps.approval.outputs.request-id }}
          grant: ${{ steps.approval.outputs.grant }}
          outcome: ${{ job.status == 'success' && 'succeeded' || 'failed' }}
```

`verify` fails the job before anything runs if the grant does not authorize exactly this payload
(wrong organization or action, expired, tampered, or a payload that changed since approval).
`report` records the outcome so the request's decision receipt reflects what actually happened; a
grant is single-use, so a second report (a retried job, a second `report` step) fails with
`already_executed` rather than silently succeeding. Put `report` under `if: always()` so a failed
deploy is still recorded as `failed`, not left unreported.

### Mandates approve instantly

Before opening a request, `mode: request` checks whether a mandate ("approve up to N deploys/day,
automatically") already covers it — same as the MCP server's `check_mandate` tool. A request is
always filed either way, so the mandate's limits count it and a receipt exists; when a mandate
covers it, the server decides it the instant it is filed: no human waits, `status` is `approved`,
and `request-id`, `grant` and `mandate-id` are all set right away, exactly as a normal approval.
`verify` and `report` steps need no special casing for this — run them unconditionally, same as
after a human approval.

Set `mandate-check: "false"` to skip this advisory pre-check (and drop the `mandate:read` scope it
needs); mandates still apply server-side, so a covered run still approves instantly, it just won't
be logged in advance and `mandate-id` will be empty.

Without a `payload` input, both `request` and `verify` use `{ service: <repository name>,
environment: <environment input>, commit: <sha>, changeSummary: <commit message> }`: the payload of
the `deployment` action that DueReason's production deployments template creates, whose
`environment` is `production` or `staging`. The ref, workflow, run and actor go along as agent
details, which workflows can route on. Pass the payload explicitly when `verify` runs with
different inputs available than `request` did (as above, or whenever the default wouldn't match,
e.g. a later step recomputing the commit).

SDK users embedding the check in their own deploy code instead of plain YAML can still call
`verifyGrant` and `client.reportExecution` directly; see the SDK's `withApproval` helper, which does
both around an arbitrary function.

### A required status check that holds even if the local gate is bypassed

A `request` + `verify` pair inside one job (above) only holds while that job runs end to end;
anyone who can merge without the job (an admin override, a force-push, a manually triggered deploy)
skips it entirely. Run `verify` with no `grant` input instead, and it looks up the newest APPROVED
request for the exact `action` + `payload` via the API and verifies that grant offline -- usable as
its own job with nothing handed to it, which is what a required GitHub status check needs:

```yaml
name: DueReason verify
on:
  pull_request:
  pull_request_review:
  workflow_dispatch:

jobs:
  duereason-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: duereason/approve@v1
        with:
          mode: verify
          api-key: ${{ secrets.DUEREASON_API_KEY }}
          organization: acme
          action: production-deploy
          payload: >-
            {"repo":"${{ github.repository }}","pr":${{ github.event.pull_request.number }},
            "head_sha":"${{ github.event.pull_request.head.sha }}","environment":"production"}
          request-if-missing: "true"
          reason: "Release ${{ github.event.pull_request.head.sha }} from PR #${{ github.event.pull_request.number }}."
```

Add the job's name (`duereason-verify` above) as a required status check in the repository's
branch protection settings for the protected branch, with **Include administrators** on. The
`pull_request_review` trigger re-runs the check on every review, so it turns green on its own once
someone approves the request in DueReason -- no second workflow to keep in sync. With
`request-if-missing: "true"`, a PR with nothing approved yet files the request instead of just
failing silently, and the job's error message links straight to it.

Put the matching `verify` step (same `action` and `payload` shape: repository, commit SHA,
environment) as the **first** step of the actual deploy job too: a branch protection rule only
ever stops a merge, never a later manual re-run, a rollback, or a deploy triggered outside this PR
flow. See the "Protect production deploys with DueReason" guide at
[duereason.com/guides/protect-production-deploys](https://duereason.com/guides/protect-production-deploys)
for the full walkthrough, including non-GitHub CI (`duereason-gate verify`, in `@duereason/gate`)
and the two-step DueReason workflow that keeps the action from approving itself.

## Inputs

| Input | Default | |
|---|---|---|
| `api-key` | | Required. From a secret |
| `mode` | `request` | `request`, `verify` or `report` |
| `reason` | | Required for `request`; required for `verify` only when `request-if-missing` is `"true"`. Why this should happen, 10-2000 characters; approvers decide on it |
| `url` | https://duereason.com | For a self-hosted DueReason |
| `action` | `deployment` | Action key configured in DueReason |
| `title` | `Deploy <repository name> <short sha> to <environment>`; for other actions `<action> from <workflow> in <repository>` | 3-200 characters, `request` only (and `verify`'s `request-if-missing` path) |
| `payload` | see above | JSON object; the grant is bound to it. `request` and `verify` |
| `environment` | `production` | Used by the default payload. `request` and `verify` |
| `timeout-minutes` | `60` | How long to wait; the request expires then. `request` only |
| `mandate-check` | `true` | Advisory pre-check and log only; the request is always filed. `"false"` skips the check. `request` only |
| `grant` | | `verify`: optional -- set it to check a grant you already hold, or omit it to look one up by `action` + `payload` instead. Required for `report`. The `grant` output of the `request` step |
| `organization` | | Required for `verify`. Your DueReason organization slug |
| `request-if-missing` | `false` | `verify` only, when no approved request is found: file one (using `reason`) and fail with a link to it instead of failing immediately. `"true"` to enable |
| `request-id` | | Required for `report`. The `request-id` output of the `request` step |
| `outcome` | | Required for `report`. `succeeded` or `failed` |
| `detail` | | Optional for `report`. Why it failed, at most 2000 characters |

## Outputs

| Output | |
|---|---|
| `status` | `request` only: `approved`, `rejected`, `expired`, `cancelled` or `timeout` |
| `request-id` | `request`: set once the request is filed, including under a mandate. `verify`: set from the verified grant's claims (the offline check) or the matched request's id (the lookup); with `request-if-missing`, set to the request it just filed when nothing was approved yet |
| `grant` | `request` only: the signed grant when approved, including under a mandate |
| `mandate-id` | `request` only: the mandate that approved this request instantly; empty when a person decided it or `mandate-check` is `"false"` |

The job summary links to the request in the DueReason console and lists who answered and what they
wrote. The waiting job holds its runner; keep `timeout-minutes` to what your approvers can meet.

## Development

The action runs `dist/index.mjs` on the runner's Node 24 (GitHub removed Node 20 from runners on
23 September 2026). A self-hosted runner needs a runner version that runs Node 24 actions, and per
GitHub, Node 24 does not support macOS 13.4 or older, nor ARM32.

`dist/index.mjs` is committed (an exception to this monorepo's general `dist/` ignore): a
`runs.using: node24` action has no separate build step when a consumer checks it out via `uses:`,
so the bundle the runner executes has to already be in the repo at that ref. Rebuild it after any
`src/` change and commit the result -- CI fails a PR where the committed `dist/` doesn't match what
`pnpm --filter @duereason/action build` produces from current `src/`:

```sh
pnpm --filter @duereason/action build   # dist/index.mjs, the action and the SDK in one file
pnpm --filter @duereason/action test
```

### Publishing a usable `uses: duereason/approve@v1`

This package is exported to its own repository by `scripts/public-repos/export.sh` in the
private monorepo, so `uses: duereason/approve@v1` as shown above resolves once that repository
is pushed under the `duereason/approve` name [VERIFY with Leszek] and a maintainer tags it there
following semver-ish major tags: push `action-v1` (and move it forward, e.g. `action-v1.2`)
pointing at the commit with the matching committed `dist/`, matching the convention consumers
expect from `@v1` in the README. Until the first tag exists, pin `uses:` to a commit SHA
instead.

## Links

- Guides: https://duereason.com/guides/protect-production-deploys
- Contact: https://duereason.com/contact
- Security: [SECURITY.md](./SECURITY.md)
- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md), [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)

## License

MIT, see [LICENSE](./LICENSE).
