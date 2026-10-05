#!/usr/bin/env bun
/**
 * Keep the decomp service alive.
 *
 *     bun scripts/supervise.ts
 *
 * WHY THIS EXISTS
 * ---------------
 * The service was started as a detached background process with no parent.
 * When a one-character SQL error took its write path down, three things were
 * true at once: nothing restarted it, nothing noticed, and `--watch` could not
 * help because the process had not changed -- only its behaviour had. It
 * served errors for 75 minutes while four agents kept submitting work.
 *
 * `--watch` reloads on EDIT. It does not restart on EXIT. This does both:
 *
 *   - respawns the child whenever it exits, with backoff, forever
 *   - polls /api/health and restarts a process that is listening but BROKEN,
 *     which is the failure mode that actually happened
 *   - refuses to start a second copy, because two supervisors means two
 *     services fighting for one port and one database
 *
 * It is deliberately dependency-free and does no work of its own: a
 * supervisor that can fail in interesting ways is another thing to supervise.
 */
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dir, '..');
const PORT = Number(process.env.PORT ?? 8787);
const LOCK = path.join(ROOT, 'data', 'supervisor.pid');

/** How long a newly started child gets before health is enforced. The boot
 *  path ingests the subject, which takes a few seconds on a cold cache. */
const GRACE_MS = 30_000;
/** Consecutive failed probes before a listening-but-broken child is killed.
 *  More than one, so a single slow response is not treated as death. */
const SICK_LIMIT = 3;
const PROBE_MS = 10_000;

const stamp = () => new Date().toISOString().slice(11, 19);
const log = (m: string) => console.log(`[${stamp()}] supervisor: ${m}`);

// One supervisor. A second would fight the first over the port and the
// database, which is how a hand-started worker produced two of everything
// earlier in this project.
if (existsSync(LOCK)) {
  const held = Number(readFileSync(LOCK, 'utf8').trim());
  try {
    process.kill(held, 0);
    console.error(
      `a supervisor is already running (pid ${held}). Stop it first; ` +
        `two supervisors means two services on one port and one database.`,
    );
    process.exit(2);
  } catch {
    log(`taking over a stale lock from pid ${held}`);
  }
}
writeFileSync(LOCK, String(process.pid));

let child: ReturnType<typeof spawn> | null = null;
let restarts = 0;
let startedAt = 0;
let sick = 0;
let stopping = false;

const start = () => {
  startedAt = Date.now();
  sick = 0;
  child = spawn('bun', ['--watch', 'src/main.ts'], {
    cwd: ROOT,
    stdio: 'inherit',
    env: { ...process.env, PORT: String(PORT) },
  });
  log(`started pid ${child.pid}${restarts ? ` (restart ${restarts})` : ''}`);

  child.on('exit', (code, signal) => {
    if (stopping) return;
    restarts++;
    // Backoff caps at 10s: a service that cannot start should keep retrying
    // loudly rather than give up, because giving up is the outage.
    const wait = Math.min(10_000, 500 * 2 ** Math.min(restarts, 5));
    log(`child exited (code ${code}, signal ${signal}); restarting in ${wait}ms`);
    setTimeout(start, wait);
  });
};

/** Listening is not the same as working. This is the check the old health
 *  endpoint could not make. */
const probe = async () => {
  if (child === null || stopping) return;
  if (Date.now() - startedAt < GRACE_MS) return;
  try {
    const r = await fetch(`http://127.0.0.1:${PORT}/api/health`, {
      signal: AbortSignal.timeout(5000),
    });
    const body = (await r.json()) as { ok?: boolean; checks?: { name: string; ok: boolean; detail: string }[] };
    if (r.ok && body.ok === true) {
      if (sick > 0) log(`healthy again after ${sick} failed probe(s)`);
      sick = 0;
      return;
    }
    sick++;
    const failing = (body.checks ?? []).filter((c) => !c.ok);
    log(
      `UNHEALTHY (${sick}/${SICK_LIMIT}) HTTP ${r.status}` +
        (failing.length ? ` -- ${failing.map((c) => `${c.name}: ${c.detail}`).join('; ')}` : ''),
    );
  } catch (e) {
    sick++;
    log(`probe failed (${sick}/${SICK_LIMIT}): ${e instanceof Error ? e.message : String(e)}`);
  }

  if (sick >= SICK_LIMIT && child !== null) {
    // Capture THIS child. Reading `child` inside the timeout reads whatever
    // is current when it fires, which is the replacement -- the first version
    // of this file SIGKILLed each healthy new child five seconds after
    // starting it, and called that supervision.
    const doomed = child;
    log(`restarting pid ${doomed.pid}: listening but not working`);
    sick = 0;
    doomed.kill('SIGTERM');
    setTimeout(() => {
      if (!doomed.killed) doomed.kill('SIGKILL');
    }, 5000);
  }
};

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    stopping = true;
    log(`${sig}: stopping child and releasing the lock`);
    child?.kill(sig);
    try {
      unlinkSync(LOCK);
    } catch {
      /* already gone */
    }
    process.exit(0);
  });
}

start();
setInterval(() => void probe(), PROBE_MS);
log(`supervising port ${PORT}; health probed every ${PROBE_MS / 1000}s`);
