import path from 'node:path';

/**
 * Where the generated browser-build tree is written.
 *
 * WHY THIS EXISTS
 * ---------------
 * The service's portable job ran `generate(Option.none())`, which records each
 * file's outcome in `port_files` and writes NOTHING. So the tree on disk --
 * 2,490 files under `decomp/port/` -- was the output of `decomp/portable.py`,
 * last run on 4 October, and every one of them carried a header saying
 * `GENERATED ... by decomp/portable.py`.
 *
 * That is two implementations of one conversion with the service's output
 * never landing anywhere a person would look, which is exactly how this
 * project once shipped 6,953 blocks of which 1,450 were real. A stale
 * generated artifact answers a question wrongly where a missing one asks it,
 * and the audit compiled a temp directory, so nothing compared the two or
 * could have.
 *
 * The service is now the only producer and writes here. `generate` already
 * removes files in the target whose source no longer exists, so the Python
 * tree is retired by being overwritten rather than by anyone remembering to
 * delete it.
 */
const WORK_ROOT = path.resolve(
  process.env.DECOMP_WORK ?? path.join(import.meta.dir, '../../../../aoe2-in-browser'),
);

/** The rendered tree the WebAssembly build compiles. */
export const PORTABLE_TREE_PATH = path.join(WORK_ROOT, 'decomp/port');
