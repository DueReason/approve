import { run } from "./run";

// GitHub sends SIGINT, then SIGTERM, when the job is cancelled: withdraw the request.
const cancelled = new AbortController();
process.once("SIGINT", () => cancelled.abort());
process.once("SIGTERM", () => cancelled.abort());

process.exitCode = await run(process.env, { signal: cancelled.signal });
