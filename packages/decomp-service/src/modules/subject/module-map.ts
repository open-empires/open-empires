import { Data, Option, Result } from 'effect';
import { GuestMapError, type GuestReadError } from './interface';
import { GuestMemory, hex } from './guest-memory';

/**
 * The first thread's TEB sits at the top of the user address space. Which page
 * it occupies depends on how many threads were created before the dump, so the
 * candidates are probed and the PEB each one yields is validated.
 */
const TEB_CANDIDATES: ReadonlyArray<number> = Array.from(
  { length: 16 },
  (_, i) => 0x7ffdf000 - i * 0x1000,
);

/** One entry of a module's export directory. */
export interface GuestExport {
  readonly ordinal: number;
  /** Absent for an export published by ordinal only. */
  readonly name: Option.Option<string>;
  /** Absent for a forwarder: it has no code in this module. */
  readonly va: Option.Option<number>;
  /** "OTHERDLL.Name" or "OTHERDLL.#13". */
  readonly forwarder: Option.Option<string>;
}

export interface GuestModule {
  readonly base: number;
  readonly size: number;
  readonly path: string;
  readonly name: string;
  /** Lower-cased file name, for matching an import descriptor's DLL. */
  readonly key: string;
  readonly exports: ReadonlyArray<GuestExport>;
  /** Why this module publishes no exports here. A fact, not a gap to fill. */
  readonly exportError: Option.Option<string>;
}

/**
 * What a guest address actually is.
 *
 * `ExportExact`  the address IS an export's entry point.
 * `ExportOffset` the address is `offset` bytes past the nearest export at or
 *                below it in the same module. NOT a claim that it belongs to
 *                that function -- only that no export starts between them.
 * `ModuleOnly`   the address is inside the module but no export starts at or
 *                below it.
 *
 * Nothing here is ever rounded to a name.
 */
export type Resolution = Data.TaggedEnum<{
  ExportExact: {
    readonly module: string;
    readonly name: Option.Option<string>;
    readonly ordinal: number;
    /** Every export name at this exact address. The address alone cannot
     *  choose between MCIWndCreate and MCIWndCreateA, so all are reported. */
    readonly aliases: ReadonlyArray<string>;
  };
  ExportOffset: {
    readonly module: string;
    readonly name: Option.Option<string>;
    readonly ordinal: number;
    readonly offset: number;
  };
  ModuleOnly: { readonly module: string };
}>;
export const Resolution = Data.taggedEnum<Resolution>();

/** How to write an export: its name, or `#ordinal` when it has none. */
const member = (name: Option.Option<string>, ordinal: number): string =>
  Option.getOrElse(name, () => `#${ordinal}`);

export const describeResolution = (resolution: Resolution): string =>
  Resolution.$match(resolution, {
    ExportExact: (r) => `${r.module}!${member(r.name, r.ordinal)}`,
    ExportOffset: (r) =>
      `${r.module}!${member(r.name, r.ordinal)}+0x${r.offset.toString(16)}`,
    ModuleOnly: (r) => `${r.module}+?`,
  });

export const resolutionName = (resolution: Resolution): Option.Option<string> =>
  Resolution.$match(resolution, {
    ExportExact: (r) => r.name,
    ExportOffset: (r) => r.name,
    ModuleOnly: () => Option.none<string>(),
  });

interface ModuleIndex {
  readonly module: GuestModule;
  /** Exports with an address, ascending by (va, ordinal). */
  readonly addressable: ReadonlyArray<GuestExport & { readonly va: Option.Some<number> }>;
  readonly byName: ReadonlyMap<string, GuestExport>;
  readonly byOrdinal: ReadonlyMap<number, GuestExport>;
}

/**
 * Every module mapped in the guest, with its exports, addressable by VA.
 *
 * Modules come from the PEB loader list, not from scanning memory for "MZ".
 * The loader list is the operating system's own record -- base, mapped size
 * and full path for each module -- so a module cannot be missed, counted
 * twice, or given a size guessed from its headers. The walk is validated
 * against the subject before it is trusted: the PEB's ImageBaseAddress must
 * equal the subject's image base.
 */
export class ModuleMap {
  private readonly indices: ReadonlyArray<ModuleIndex>;
  private readonly byKey: ReadonlyMap<string, ModuleIndex>;
  /**
   * (publishing module, implementing module, implemented name) -> the name the
   * publisher exports it under. A forwarded export has no code of its own, so
   * an address resolves to the module that really implements it:
   * kernel32!GetLastError resolves as ntdll!RtlGetLastWin32Error. This
   * recovers the name the game was actually linked against.
   */
  private readonly aliases: ReadonlyMap<string, string>;

  private constructor(readonly modules: ReadonlyArray<GuestModule>) {
    this.indices = modules.map((module) => {
      const addressable = module.exports
        .filter((e): e is GuestExport & { va: Option.Some<number> } => Option.isSome(e.va))
        .sort((a, b) => a.va.value - b.va.value || a.ordinal - b.ordinal);
      const byName = new Map<string, GuestExport>();
      const byOrdinal = new Map<number, GuestExport>();
      for (const e of module.exports) {
        if (Option.isSome(e.name)) byName.set(e.name.value, e);
        byOrdinal.set(e.ordinal, e);
      }
      return { module, addressable, byName, byOrdinal };
    });
    this.byKey = new Map(this.indices.map((i) => [i.module.key, i]));
    const aliases = new Map<string, string>();
    for (const owner of this.indices) {
      for (const e of owner.module.exports) {
        if (Option.isNone(e.forwarder) || Option.isNone(e.name)) continue;
        const next = this.followForwarder(e.forwarder.value);
        if (Option.isNone(next)) continue;
        const { module: target, export: implemented } = next.value;
        if (Option.isNone(implemented.name)) continue;
        aliases.set(
          `${owner.module.key}\u0000${target.module.key}\u0000${implemented.name.value}`,
          e.name.value,
        );
      }
    }
    this.aliases = aliases;
  }

  private followForwarder(
    forwarder: string,
  ): Option.Option<{ readonly module: ModuleIndex; readonly export: GuestExport }> {
    const dot = forwarder.lastIndexOf('.');
    if (dot < 0) return Option.none();
    const dll = forwarder.slice(0, dot);
    const name = forwarder.slice(dot + 1);
    const target = this.byKey.get(dll.toLowerCase()) ?? this.byKey.get(`${dll.toLowerCase()}.dll`);
    if (target === undefined) return Option.none();
    const found = name.startsWith('#')
      ? target.byOrdinal.get(Number.parseInt(name.slice(1), 10))
      : target.byName.get(name);
    if (found === undefined) return Option.none();
    return Option.some({ module: target, export: found });
  }

  // ---------------------------------------------------------------- loading

  static load(
    memory: GuestMemory,
    expectImageBase: number,
  ): Result.Result<ModuleMap, GuestReadError | GuestMapError> {
    return Result.gen(function* () {
      const listed = yield* walkLoaderList(memory, expectImageBase);
      const modules = listed
        .slice()
        .sort((a, b) => a.base - b.base)
        .map((m) => parseExports(memory, m));
      return new ModuleMap(modules);
    });
  }

  // ----------------------------------------------------------------- lookup

  moduleAt(va: number): Option.Option<GuestModule> {
    for (const { module } of this.indices) {
      if (va >= module.base && va < module.base + module.size) return Option.some(module);
    }
    return Option.none();
  }

  moduleNamed(dll: string): Option.Option<GuestModule> {
    const found = this.byKey.get(dll.toLowerCase());
    return found === undefined ? Option.none() : Option.some(found.module);
  }

  /** The export this address is, or sits after. Absent outside every module. */
  resolve(va: number): Option.Option<Resolution> {
    const index = this.indices.find(
      ({ module }) => va >= module.base && va < module.base + module.size,
    );
    if (index === undefined) return Option.none();
    const best = lastAtOrBelow(index.addressable, va);
    if (Option.isNone(best)) {
      return Option.some(Resolution.ModuleOnly({ module: index.module.name }));
    }
    const entry = best.value;
    if (entry.va.value === va) {
      const aliases = index.addressable
        .filter((e) => e.va.value === va)
        .flatMap((e) => (Option.isSome(e.name) ? [e.name.value] : []))
        .sort();
      return Option.some(
        Resolution.ExportExact({
          module: index.module.name,
          name: entry.name,
          ordinal: entry.ordinal,
          aliases,
        }),
      );
    }
    return Option.some(
      Resolution.ExportOffset({
        module: index.module.name,
        name: entry.name,
        ordinal: entry.ordinal,
        offset: va - entry.va.value,
      }),
    );
  }

  /** The name `dll` publishes for an export that lives in another module. */
  aliasIn(dll: string, resolution: Resolution): Option.Option<string> {
    const name = resolutionName(resolution);
    if (Option.isNone(name)) return Option.none();
    const owner = Resolution.$match(resolution, {
      ExportExact: (r) => r.module,
      ExportOffset: (r) => r.module,
      ModuleOnly: (r) => r.module,
    });
    const found = this.aliases.get(
      `${dll.toLowerCase()}\u0000${owner.toLowerCase()}\u0000${name.value}`,
    );
    return found === undefined ? Option.none() : Option.some(found);
  }
}

/** The first element holding the greatest address at or below `va`. */
const lastAtOrBelow = (
  sorted: ReadonlyArray<GuestExport & { readonly va: Option.Some<number> }>,
  va: number,
): Option.Option<GuestExport & { readonly va: Option.Some<number> }> => {
  let lo = 0;
  let hi = sorted.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid]!.va.value <= va) {
      found = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  if (found < 0) return Option.none();
  const address = sorted[found]!.va.value;
  let first = found;
  while (first > 0 && sorted[first - 1]!.va.value === address) first--;
  return Option.some(sorted[first]!);
};

// ------------------------------------------------------------------ internals

interface ListedModule {
  readonly base: number;
  readonly size: number;
  readonly path: string;
}

/** Enumerate modules from the PEB, validating the PEB before trusting it. */
const walkLoaderList = (
  memory: GuestMemory,
  expectImageBase: number,
): Result.Result<ReadonlyArray<ListedModule>, GuestReadError | GuestMapError> => {
  for (const teb of TEB_CANDIDATES) {
    const peb = memory.u32(teb + 0x30);
    if (Option.isNone(peb)) continue;
    if (!(peb.value > 0x7f000000 && peb.value < 0x80000000)) continue;
    const imageBase = memory.u32(peb.value + 0x08);
    if (Option.isNone(imageBase) || imageBase.value !== expectImageBase) continue;
    const ldr = memory.u32(peb.value + 0x0c);
    if (Option.isNone(ldr) || ldr.value === 0) continue;
    return walkModuleList(memory, ldr.value + 0x0c);
  }
  return Result.fail(
    new GuestMapError({
      reason:
        `no TEB candidate yielded a PEB whose ImageBaseAddress is ${hex(expectImageBase)}`,
    }),
  );
};

const walkModuleList = (
  memory: GuestMemory,
  head: number,
): Result.Result<ReadonlyArray<ListedModule>, GuestReadError> =>
  Result.gen(function* () {
    const out: ListedModule[] = [];
    let cursor = yield* memory.requireU32(head);
    for (let seen = 0; cursor !== 0 && cursor !== head && seen < 1024; seen++) {
      const base = yield* memory.requireU32(cursor + 0x18);
      const size = yield* memory.requireU32(cursor + 0x20);
      const nameLength = yield* memory.requireU16(cursor + 0x24);
      const nameBuffer = yield* memory.requireU32(cursor + 0x28);
      const path = nameBuffer !== 0 && nameLength !== 0
        ? memory.wstr(nameBuffer, nameLength)
        : Option.none<string>();
      if (base !== 0 && size !== 0 && Option.isSome(path)) {
        out.push({ base, size, path: path.value });
      }
      cursor = yield* memory.requireU32(cursor);
    }
    return out satisfies ReadonlyArray<ListedModule>;
  });

const EXPORT_DIRECTORY_RVA_AT = 96;
const EXPORT_DIRECTORY_SIZE_AT = 100;

/**
 * Fill a module's exports from its export directory, or record why they are
 * absent. An unreadable page is recorded as the reason, never as zero exports:
 * "this module publishes nothing" and "this module's pages are not in the
 * dump" are different answers and must not be confused.
 */
const parseExports = (memory: GuestMemory, listed: ListedModule): GuestModule => {
  const name = listed.path.split('\\').pop() ?? listed.path;
  const shell = {
    base: listed.base,
    size: listed.size,
    path: listed.path,
    name,
    key: name.toLowerCase(),
  };
  const withError = (reason: string): GuestModule => ({
    ...shell,
    exports: [],
    exportError: Option.some(reason),
  });

  const parsed = Result.gen(function* () {
    const mz = memory.read(listed.base, 2);
    if (Option.isNone(mz) || mz.value[0] !== 0x4d || mz.value[1] !== 0x5a) {
      return yield* Result.fail('no MZ at base');
    }
    const ntOffset = yield* readOr(memory.u32(listed.base + 0x3c), listed.base + 0x3c);
    const nt = listed.base + ntOffset;
    const signature = memory.read(nt, 4);
    if (
      Option.isNone(signature) ||
      signature.value[0] !== 0x50 ||
      signature.value[1] !== 0x45 ||
      signature.value[2] !== 0 ||
      signature.value[3] !== 0
    ) {
      return yield* Result.fail('no PE signature');
    }
    const optional = nt + 24;
    const magic = yield* readOr(memory.u16(optional), optional);
    if (magic !== 0x10b) {
      return yield* Result.fail(`optional header magic 0x${magic.toString(16)} is not PE32`);
    }
    const directoryRva = yield* readOr(
      memory.u32(optional + EXPORT_DIRECTORY_RVA_AT),
      optional + EXPORT_DIRECTORY_RVA_AT,
    );
    const directorySize = yield* readOr(
      memory.u32(optional + EXPORT_DIRECTORY_SIZE_AT),
      optional + EXPORT_DIRECTORY_SIZE_AT,
    );
    if (directoryRva === 0) return yield* Result.fail('no export directory');
    const directory = listed.base + directoryRva;
    const functionCount = yield* readOr(memory.u32(directory + 0x14), directory + 0x14);
    const nameCount = yield* readOr(memory.u32(directory + 0x18), directory + 0x18);
    const ordinalBase = yield* readOr(memory.u32(directory + 0x10), directory + 0x10);
    const functionTable = listed.base + (yield* readOr(memory.u32(directory + 0x1c), directory + 0x1c));
    const nameTable = listed.base + (yield* readOr(memory.u32(directory + 0x20), directory + 0x20));
    const ordinalTable = listed.base + (yield* readOr(memory.u32(directory + 0x24), directory + 0x24));

    // function-table index -> name, from the parallel name/ordinal arrays
    const names = new Map<number, string>();
    for (let i = 0; i < nameCount; i++) {
      const index = yield* readOr(memory.u16(ordinalTable + 2 * i), ordinalTable + 2 * i);
      const nameRva = yield* readOr(memory.u32(nameTable + 4 * i), nameTable + 4 * i);
      const text = memory.cstr(listed.base + nameRva);
      if (Option.isSome(text)) names.set(index, text.value);
    }

    const exports: GuestExport[] = [];
    for (let i = 0; i < functionCount; i++) {
      const rva = yield* readOr(memory.u32(functionTable + 4 * i), functionTable + 4 * i);
      if (rva === 0) continue; // a hole in the ordinal space
      const exported = names.get(i);
      const exportName = exported === undefined ? Option.none<string>() : Option.some(exported);
      // An RVA inside the export directory is a forwarder string.
      if (rva >= directoryRva && rva < directoryRva + directorySize) {
        exports.push({
          ordinal: ordinalBase + i,
          name: exportName,
          va: Option.none(),
          forwarder: memory.cstr(listed.base + rva),
        });
      } else {
        exports.push({
          ordinal: ordinalBase + i,
          name: exportName,
          va: Option.some(listed.base + rva),
          forwarder: Option.none(),
        });
      }
    }
    exports.sort(
      (a, b) =>
        Number(Option.isNone(a.va)) - Number(Option.isNone(b.va)) ||
        Option.getOrElse(a.va, () => 0) - Option.getOrElse(b.va, () => 0) ||
        a.ordinal - b.ordinal,
    );
    return exports satisfies ReadonlyArray<GuestExport>;
  });

  return Result.isFailure(parsed)
    ? withError(parsed.failure)
    : { ...shell, exports: parsed.success, exportError: Option.none() };
};

const readOr = (value: Option.Option<number>, va: number): Result.Result<number, string> =>
  Result.fromOption(value, () => `page for ${hex(va)} is not resident`);
