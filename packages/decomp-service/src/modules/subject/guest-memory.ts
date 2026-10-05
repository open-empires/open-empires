import { Option, Result } from 'effect';
import { GuestReadError, type PagingMode } from './interface';

const PAGE_SIZE = 0x1000;
const PRESENT = 1;
/** PS in a page-directory entry: the entry maps a large page directly. */
const LARGE_PAGE = 0x80;

const LATIN1 = new TextDecoder('latin1');
const UTF16LE = new TextDecoder('utf-16le');

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

/**
 * The guest's VIRTUAL address space, read out of a physical RAM image by
 * walking the page tables CR3 points at.
 *
 * Needed because the subject's own KERNEL32 and USER32 import names cannot be
 * recovered from the subject at all: those two descriptors have
 * OriginalFirstThunk == 0, so the loader read the names out of the import
 * table and overwrote them in place with resolved addresses -- 110 + 76 =
 * exactly the 186 that are missing. The only route left is the other
 * direction, and every structure it needs lives elsewhere in this address
 * space.
 *
 * Two reading tiers, and the difference is the point:
 *   - `read` / `u32` / `u16` / `cstr` / `wstr` report PRESENCE. A page that is
 *     not resident comes back absent, because `00 00` is a valid x86
 *     instruction and unreadable bytes once became 64 phantom code blocks.
 *   - `requireRead` / `requireU32` / `requireU16` / `requireWstr` are for the
 *     places where absence is a failure, and name the address that was missing.
 */
export class GuestMemory {
  private readonly view: DataView;

  private constructor(
    private readonly ram: Uint8Array,
    private readonly cr3: number,
    readonly mode: PagingMode,
  ) {
    this.view = new DataView(ram.buffer, ram.byteOffset, ram.byteLength);
  }

  /**
   * Pin the paging mode by reproducing bytes already known to be at `probeVa`,
   * rather than assuming which mode the dumped machine was in. Absent means
   * neither mode reproduces them, so nothing read through either could be
   * trusted.
   */
  static detect(input: {
    readonly ram: Uint8Array;
    readonly cr3: number;
    readonly probeVa: number;
    readonly expect: Uint8Array;
  }): Option.Option<GuestMemory> {
    const modes: ReadonlyArray<PagingMode> = ['legacy', 'pae'];
    for (const mode of modes) {
      const candidate = new GuestMemory(input.ram, input.cr3, mode);
      const got = candidate.read(input.probeVa, input.expect.length);
      if (Option.isSome(got) && bytesEqual(got.value, input.expect)) {
        return Option.some(candidate);
      }
    }
    return Option.none();
  }

  /**
   * Find BOTH the page-directory root and the paging mode, by reproducing
   * bytes already known to be at `probeVa`.
   *
   * `detect` pins the mode this way but takes CR3 on trust, so CR3 was a
   * hand-recorded constant -- 0x1624d000 for the first dump. That makes every
   * new dump a code change, and it left the second dump unusable: it was
   * captured specifically to exercise the 54 import slots the copy protection
   * had not yet recorded, and nothing could read it because nobody knew its
   * CR3.
   *
   * THE PROBE HAS TO BE BIG. A dump holds nine processes and the game image
   * is mapped in eight of them, so the first 16 bytes -- an MZ header
   * identical in every one -- admit EIGHT candidate roots. Measured on the
   * known dump: 16 bytes leaves 8 candidates, 4KB leaves exactly one, and
   * that one is the value that had been recorded by other means. Pass at
   * least a page.
   *
   * Ambiguity is reported, never resolved by picking the first. Reading the
   * wrong process still yields the right CODE -- the image is identical --
   * while yielding the wrong per-process state, and the import cache this
   * exists to read is exactly that kind of state. A wrong answer here looks
   * entirely correct.
   */
  static locate(input: {
    readonly ram: Uint8Array;
    readonly probeVa: number;
    readonly expect: Uint8Array;
    /** Tried first, so a known dump costs one attempt instead of a scan. It
     *  must still satisfy the probe; a stale constant does not get to win. */
    readonly hint?: number;
  }):
    | { readonly _tag: 'Located'; readonly cr3: number; readonly memory: GuestMemory }
    | { readonly _tag: 'Ambiguous'; readonly candidates: ReadonlyArray<number> }
    | { readonly _tag: 'NotFound' } {
    const attempt = (cr3: number): Option.Option<GuestMemory> =>
      GuestMemory.detect({
        ram: input.ram,
        cr3,
        probeVa: input.probeVa,
        expect: input.expect,
      });

    if (input.hint !== undefined) {
      const hinted = attempt(input.hint);
      if (Option.isSome(hinted)) {
        return { _tag: 'Located', cr3: input.hint, memory: hinted.value };
      }
    }

    // TWO STAGES. The full probe is a page, and reading a page through a
    // candidate's page tables allocates; doing that for all 131,072
    // page-aligned candidates in a 512MB image made this the most expensive
    // thing in the test suite and intermittently exhausted it.
    //
    // Matching the first 16 bytes is a NECESSARY condition for matching the
    // page, because those 16 bytes are part of it. So the cheap probe rejects
    // everything but a handful -- eight, on the known dump, being the eight
    // processes that map the image -- and only those are asked the question
    // that actually discriminates. Same answer, a fraction of the work.
    const cheap = input.expect.subarray(0, Math.min(16, input.expect.length));
    const shortlist: number[] = [];
    for (let cr3 = 0; cr3 + 0x1000 <= input.ram.length; cr3 += 0x1000) {
      const rough = GuestMemory.detect({
        ram: input.ram,
        cr3,
        probeVa: input.probeVa,
        expect: cheap,
      });
      if (Option.isSome(rough)) shortlist.push(cr3);
    }

    const candidates: number[] = [];
    let first: GuestMemory | undefined;
    for (const cr3 of shortlist) {
      const found = attempt(cr3);
      if (Option.isNone(found)) continue;
      candidates.push(cr3);
      first ??= found.value;
      // Two is already too many to choose between; stop rather than scan on.
      if (candidates.length > 1) return { _tag: 'Ambiguous', candidates };
    }
    if (candidates.length === 1 && first !== undefined) {
      return { _tag: 'Located', cr3: candidates[0]!, memory: first };
    }
    return { _tag: 'NotFound' };
  }

  // ------------------------------------------------------------- physical

  private phys(address: number, length: number): Option.Option<Uint8Array> {
    if (address < 0 || address + length > this.ram.length) return Option.none();
    return Option.some(this.ram.slice(address, address + length));
  }

  private physU32(address: number): Option.Option<number> {
    if (address < 0 || address + 4 > this.ram.length) return Option.none();
    return Option.some(this.view.getUint32(address, true));
  }

  private physU64(address: number): Option.Option<bigint> {
    if (address < 0 || address + 8 > this.ram.length) return Option.none();
    return Option.some(this.view.getBigUint64(address, true));
  }

  // ------------------------------------------------------------ translation

  private translateLegacy(va: number): Option.Option<number> {
    const pde = this.physU32(((this.cr3 & 0xfffff000) >>> 0) + ((va >>> 22) << 2));
    if (Option.isNone(pde) || (pde.value & PRESENT) === 0) return Option.none();
    if ((pde.value & LARGE_PAGE) !== 0) {
      return Option.some(((pde.value & 0xffc00000) | (va & 0x3fffff)) >>> 0);
    }
    const pte = this.physU32(
      ((pde.value & 0xfffff000) >>> 0) + (((va >>> 12) & 0x3ff) << 2),
    );
    if (Option.isNone(pte) || (pte.value & PRESENT) === 0) return Option.none();
    return Option.some(((pte.value & 0xfffff000) | (va & 0xfff)) >>> 0);
  }

  private translatePae(va: number): Option.Option<number> {
    const frame = 0x000ffffffffff000n;
    const pdpte = this.physU64(((this.cr3 & 0xffffffe0) >>> 0) + ((va >>> 30) << 3));
    if (Option.isNone(pdpte) || (pdpte.value & 1n) === 0n) return Option.none();
    const pde = this.physU64(
      Number(pdpte.value & frame) + (((va >>> 21) & 0x1ff) << 3),
    );
    if (Option.isNone(pde) || (pde.value & 1n) === 0n) return Option.none();
    if ((pde.value & BigInt(LARGE_PAGE)) !== 0n) {
      return Option.some(
        Number((pde.value & 0x000fffffffe00000n) | BigInt(va & 0x1fffff)),
      );
    }
    const pte = this.physU64(Number(pde.value & frame) + (((va >>> 12) & 0x1ff) << 3));
    if (Option.isNone(pte) || (pte.value & 1n) === 0n) return Option.none();
    return Option.some(Number((pte.value & frame) | BigInt(va & 0xfff)));
  }

  translate(va: number): Option.Option<number> {
    return this.mode === 'pae' ? this.translatePae(va) : this.translateLegacy(va);
  }

  // ------------------------------------------------------------------ reads

  /** Virtual bytes, walked page by page because a run may span pages. */
  read(va: number, length: number): Option.Option<Uint8Array> {
    const out = new Uint8Array(length);
    let written = 0;
    let at = va;
    let left = length;
    while (left > 0) {
      const physical = this.translate(at);
      if (Option.isNone(physical)) return Option.none();
      const take = Math.min(left, PAGE_SIZE - (at & 0xfff));
      const chunk = this.phys(physical.value, take);
      if (Option.isNone(chunk) || chunk.value.length !== take) return Option.none();
      out.set(chunk.value, written);
      written += take;
      at += take;
      left -= take;
    }
    return Option.some(out);
  }

  u32(va: number): Option.Option<number> {
    return Option.map(this.read(va, 4), (b) =>
      new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true),
    );
  }

  u16(va: number): Option.Option<number> {
    return Option.map(this.read(va, 2), (b) =>
      new DataView(b.buffer, b.byteOffset, 2).getUint16(0, true),
    );
  }

  /**
   * A NUL-terminated byte string. `limit` bytes must all be resident, which is
   * the reference implementation's behaviour: a string whose page is resident
   * but whose neighbour is not comes back absent rather than truncated.
   */
  cstr(va: number, limit = 512): Option.Option<string> {
    return Option.map(this.read(va, limit), (bytes) => {
      const end = bytes.indexOf(0);
      return LATIN1.decode(bytes.subarray(0, end >= 0 ? end : limit));
    });
  }

  /** A UTF-16 string of exactly `byteLength` bytes, as the loader list stores. */
  wstr(va: number, byteLength: number): Option.Option<string> {
    return Option.map(this.read(va, byteLength), (bytes) => UTF16LE.decode(bytes));
  }

  // -------------------------------------------------- reads that must succeed

  requireRead(va: number, length: number): Result.Result<Uint8Array, GuestReadError> {
    return Result.fromOption(
      this.read(va, length),
      () =>
        new GuestReadError({
          va,
          reason: `the ${length}-byte run at ${hex(va)} is not fully resident`,
        }),
    );
  }

  requireU32(va: number): Result.Result<number, GuestReadError> {
    return Result.fromOption(
      this.u32(va),
      () => new GuestReadError({ va, reason: `the page for ${hex(va)} is not resident` }),
    );
  }

  requireU16(va: number): Result.Result<number, GuestReadError> {
    return Result.fromOption(
      this.u16(va),
      () => new GuestReadError({ va, reason: `the page for ${hex(va)} is not resident` }),
    );
  }

  requireWstr(va: number, byteLength: number): Result.Result<string, GuestReadError> {
    return Result.fromOption(
      this.wstr(va, byteLength),
      () =>
        new GuestReadError({
          va,
          reason: `the ${byteLength}-byte string at ${hex(va)} is not fully resident`,
        }),
    );
  }
}

export const hex = (value: number): string => `0x${(value >>> 0).toString(16).padStart(8, '0')}`;
