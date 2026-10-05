import { Option, Result } from 'effect';
import { SubjectParseError, type GuestReadError } from './interface';
import type { GuestMemory } from './guest-memory';

/**
 * SafeDisc's import-redirection tables, read out of the running game's memory.
 *
 * The game's KERNEL32 and USER32 import descriptors have OriginalFirstThunk
 * == 0, so the 186 names they carried were overwritten in place by the loader.
 * Those slots do not hold API addresses either: each holds the address of a
 * SafeDisc stub, and SafeDisc resolves the real API at every call. Recovering
 * the names therefore means reading SafeDisc's own tables.
 *
 * Every constant below was read out of the dispatcher's instructions, not
 * guessed. The dispatcher lives at 0x00CC3270, inside dplayerx.dll (SafeDisc's
 * loader, mapped at 0x00CC0000), and all 186 stubs call it through a pointer
 * in their own body. Its arguments are (module_index, import_index,
 * frame_pointer), pushed by the stub:
 *
 *     00CC32BA  mov  eax, [eax]                 ; eax = [ebp+0x3C], the game's
 *     00CC32BC  sub  eax, 6                     ;   return address, minus 6
 *     00CC32D5  mov  eax, [ebp+8]               ; module_index
 *     00CC32D8  imul eax, eax, 0x89             ; MODULE_STRIDE
 *     00CC32DE  mov  ecx, [eax + 0xCE3E93]      ; -> the module's record array
 *     00CC3315  mov  ecx, [eax + 2]             ; disp32 of `call [slot]`
 *     00CC332A  imul edx, edx, 0x377            ; RECORD_SIZE
 *     00CC3336  cmp  ecx, [eax + edx + 0x36B]   ; record.slot
 *   and in the lookup it calls at 0x00CC23D0:
 *     00CC23EE  mov  ecx, 0x65                  ; BUCKET_COUNT = 101
 *     00CC23F3  div  ecx                        ; bucket = call_site % 101
 *     00CC2425  lea  edx, [eax + ecx*8 + 3]     ; record + 3 + bucket*8
 *     00CC2453  mov  ecx, [eax]                 ; entry.call_site
 *     00CC246A  mov  eax, [edx + 4]             ; entry.resolved_address
 *   and in the apply step at 0x00CC2260:
 *     00CC2287  add  eax, 0x24                  ; frame_pointer + 0x24
 *     00CC2293  mov  [ecx], edx                 ;   = the pushed placeholder
 *     00CC22B8  mov  esp, [ebp+0xC]             ; esp = frame_pointer
 *     00CC22BB  popal / popfd / ret             ; tail-jump into the API
 *
 * That last step is why the stub is transparent to the game: the first imm32
 * the stub pushes is a placeholder, the dispatcher overwrites it with the
 * resolved API address, and `ret` jumps there with the game's own arguments
 * and return address untouched. The placeholder is not an encoded name; it is
 * a slot to write into.
 *
 * So a record's authoritative content, for recovering names, is its hash table
 * of (call site -> resolved API address) pairs. Those are facts SafeDisc wrote
 * after resolving the import for real, and a pair survives in the dump only if
 * that call site actually executed before the snapshot.
 *
 * One consequence defeats the obvious data model and has to be stated plainly:
 * a single IAT slot does NOT correspond to a single API. The dispatcher keys
 * on the call site as well as the slot, and several distinct APIs are reached
 * through one slot. The key is the pair, never the slot alone.
 */
/**
 * The DLL the dispatcher and its tables live in, and their offsets inside it.
 *
 * The addresses above were read at the base this DLL happened to be mapped at
 * in one dump, 0x00CC0000. Nothing holds it there: in a second dump taken from
 * a fresh boot of the same machine it was at 0x00D40000, and every absolute
 * address in this file was 0x80000 short. So the base is looked up in the
 * guest's own loader list and the offsets, which ARE properties of the DLL's
 * code, are added to it.
 */
export const SAFEDISC_LOADER_DLL = 'dplayerx.dll';
export const DISPATCHER_OFFSET = 0x3270; // 0x00CC3270 - 0x00CC0000
export const MODULE_TABLE_OFFSET = 0x23e93; // mov ecx, [eax + 0xCE3E93]
export const REMAP_TABLE_OFFSET = 0x23e20; // mov edx, [ecx + 0xCE3E20]
export const MODULE_STRIDE = 0x89; // imul eax, eax, 0x89
export const RECORD_SIZE = 0x377; // imul edx, edx, 0x377
export const BUCKET_COUNT = 101; // mov ecx, 0x65 ; div ecx
export const BUCKETS_AT = 3; // lea edx, [eax + ecx*8 + 3]
const RESOLVED_AT = 0x332; // mov ecx, [eax + edx + 0x332]
const STUB_AT = 0x337; // the record's own trampoline
const SLOT_AT = 0x36b; // cmp ecx, [eax + edx + 0x36B]
const DISPATCHER_PTR_AT = 0x372; // the `call dword ptr [...]` target in the stub

/** The stub's fixed shape, and where its two imm32 operands sit. */
const STUB_TEMPLATE: ReadonlyArray<readonly [number, ReadonlyArray<number>]> = [
  [0x00, [0x68]], // push <placeholder>
  [0x05, [0x9c, 0x60, 0x54]], // pushfd ; pushad ; push esp
  [0x08, [0x68]], // push <import_index>
  [0x0d, [0x68]], // push <module_index>
  [0x12, [0xff, 0x15]], // call dword ptr [<dispatcher pointer>]
  [0x18, [0x83, 0xc4, 0x0c]], // add esp, 0xC
];
const STUB_PLACEHOLDER_AT = 0x01;
const STUB_IMPORT_INDEX_AT = 0x09;
const STUB_MODULE_INDEX_AT = 0x0e;

/**
 * How many module-table entries to probe. Which DLL each index names is not
 * stored anywhere this reads; it is established in the import map by checking
 * that every record of an index serves slots one single DLL owns.
 */
const MODULE_INDEX_COUNT = 8;

/** One (call site -> API address) pair SafeDisc cached after resolving it. */
export interface CallSiteBinding {
  readonly bucket: number;
  /** The game's return address minus six. */
  readonly callSite: number;
  /** The resolved API address it jumped to. */
  readonly target: number;
  /** Whether the entry sits in the bucket its own hash demands. */
  readonly hashOk: boolean;
}

export interface ImportRecord {
  readonly moduleIndex: number;
  readonly importIndex: number;
  /** The record's base address. */
  readonly address: number;
  /** The IAT slot this record serves. */
  readonly slot: number;
  /** The trampoline the IAT slot points at. */
  readonly stub: number;
  readonly dispatcher: number;
  /** The imm32 the stub pushes to be overwritten. */
  readonly placeholder: number;
  /** Absent when never written, which is a fact about what ran, not a gap. */
  readonly resolvedAddress: Option.Option<number>;
  readonly remappedIndex: number;
  readonly bindings: ReadonlyArray<CallSiteBinding>;
}

export interface RedirectModule {
  readonly index: number;
  readonly recordArray: number;
  readonly remapTable: number;
  readonly records: ReadonlyArray<ImportRecord>;
}

/** SafeDisc's per-module arrays of import records. */
export class RedirectTable {
  readonly records: ReadonlyArray<ImportRecord>;
  private readonly bySlot: ReadonlyMap<number, ImportRecord>;

  private constructor(readonly modules: ReadonlyArray<RedirectModule>) {
    this.records = modules.flatMap((m) => m.records);
    this.bySlot = new Map(this.records.map((r) => [r.slot, r]));
  }

  recordForSlot(slot: number): Option.Option<ImportRecord> {
    const found = this.bySlot.get(slot);
    return found === undefined ? Option.none() : Option.some(found);
  }

  static read(
    memory: GuestMemory,
    loaderBase: number,
    counts: ReadonlyMap<number, number>,
  ): Result.Result<RedirectTable, GuestReadError | SubjectParseError> {
    const moduleTable = loaderBase + MODULE_TABLE_OFFSET;
    const remapTableBase = loaderBase + REMAP_TABLE_OFFSET;
    return Result.gen(function* () {
      const modules: RedirectModule[] = [];
      for (const index of [...counts.keys()].sort((a, b) => a - b)) {
        const recordArray = yield* memory.requireU32(moduleTable + index * MODULE_STRIDE);
        const remapTable = yield* memory.requireU32(remapTableBase + index * MODULE_STRIDE);
        const records: ImportRecord[] = [];
        for (let i = 0; i < counts.get(index)!; i++) {
          records.push(yield* readRecord(memory, { index, recordArray, remapTable }, i));
        }
        modules.push({ index, recordArray, remapTable, records });
      }
      return new RedirectTable(modules);
    });
  }
}

/**
 * How many records each populated module index has, from its own stub chain.
 *
 * A module entry is populated when its record-array pointer is a readable
 * address whose first record carries the dispatcher pointer. The count is the
 * number of consecutive records that do, so it is derived from the table
 * rather than assumed from the import descriptors.
 */
export const moduleRecordCounts = (
  memory: GuestMemory,
  loaderBase: number,
): ReadonlyMap<number, number> => {
  const out = new Map<number, number>();
  for (let index = 0; index < MODULE_INDEX_COUNT; index++) {
    const array = memory.u32(loaderBase + MODULE_TABLE_OFFSET + index * MODULE_STRIDE);
    if (Option.isNone(array) || array.value === 0) continue;
    let count = 0;
    while (count < 4096) {
      const pointer = memory.u32(array.value + count * RECORD_SIZE + DISPATCHER_PTR_AT);
      if (Option.isNone(pointer) || pointer.value !== loaderBase + DISPATCHER_OFFSET) break;
      count++;
    }
    if (count > 0) out.set(index, count);
  }
  return out;
};

const readRecord = (
  memory: GuestMemory,
  module: { readonly index: number; readonly recordArray: number; readonly remapTable: number },
  i: number,
): Result.Result<ImportRecord, GuestReadError | SubjectParseError> =>
  Result.gen(function* () {
    const address = module.recordArray + i * RECORD_SIZE;
    const body = yield* memory.requireRead(address, RECORD_SIZE);
    const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
    for (const [offset, expected] of STUB_TEMPLATE) {
      const at = STUB_AT + offset;
      const got = body.subarray(at, at + expected.length);
      if (!expected.every((byte, k) => got[k] === byte)) {
        return yield* Result.fail(
          new SubjectParseError({
            what: `SafeDisc record ${i} of module ${module.index}`,
            reason:
              `stub byte 0x${offset.toString(16)} is ${hexBytes(got)}, expected ` +
              hexBytes(expected),
          }),
        );
      }
    }
    const resolvedAddress = view.getUint32(RESOLVED_AT, true);
    const bindings: CallSiteBinding[] = [];
    for (let bucket = 0; bucket < BUCKET_COUNT; bucket++) {
      const at = BUCKETS_AT + bucket * 8;
      const callSite = view.getUint32(at, true);
      const target = view.getUint32(at + 4, true);
      if (callSite === 0 && target === 0) continue;
      bindings.push({
        bucket,
        callSite,
        target,
        hashOk: callSite % BUCKET_COUNT === bucket,
      });
    }
    return {
      moduleIndex: view.getUint32(STUB_AT + STUB_MODULE_INDEX_AT, true),
      importIndex: view.getUint32(STUB_AT + STUB_IMPORT_INDEX_AT, true),
      address,
      slot: view.getUint32(SLOT_AT, true),
      stub: address + STUB_AT,
      dispatcher: view.getUint32(DISPATCHER_PTR_AT, true),
      placeholder: view.getUint32(STUB_AT + STUB_PLACEHOLDER_AT, true),
      resolvedAddress: resolvedAddress === 0 ? Option.none() : Option.some(resolvedAddress),
      remappedIndex: yield* memory.requireU32(module.remapTable + 4 * i),
      bindings,
    } satisfies ImportRecord;
  });

const hexBytes = (bytes: ArrayLike<number>): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** The address span of a record's bucket array, for reporting an empty cache. */
export const bucketSpan = (record: ImportRecord): { readonly lo: number; readonly hi: number } => ({
  lo: record.address + BUCKETS_AT,
  hi: record.address + BUCKETS_AT + 8 * BUCKET_COUNT,
});
