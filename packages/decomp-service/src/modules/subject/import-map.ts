import { Option, Result } from 'effect';
import {
  GuestMapError,
  type BindingEvidence,
  type ImportMapTotals,
  type SlotResolutionKey,
} from './interface';
import type { GuestMemory } from './guest-memory';
import { hex } from './guest-memory';
import { describeResolution, ModuleMap, Resolution } from './module-map';
import { callSiteSlotOperand, type DeclaredImportSlot, type PeImage } from './pe';
import { bucketSpan, BUCKET_COUNT, type ImportRecord, type RedirectTable } from './safedisc';

const hex8 = (value: number): string => (value >>> 0).toString(16).toUpperCase().padStart(8, '0');

/** One (slot, call site) pair, which is the only key an API actually has. */
export interface SlotBinding {
  readonly callSite: number;
  readonly target: number;
  readonly bucket: number;
  readonly api: Option.Option<string>;
  readonly evidence: BindingEvidence;
  /** Why this binding names nothing. Absent when it names something. */
  readonly blockedBy: Option.Option<string>;
  /** The slot the call site's own operand names, when there is one to read. */
  readonly callOperand: Option.Option<number>;
}

export interface MappedSlot {
  readonly va: number;
  readonly dll: string;
  readonly descriptorName: Option.Option<string>;
  readonly descriptorOrdinal: Option.Option<number>;
  /** What the slot holds in the dump. Absent when its page is not resident. */
  readonly target: Option.Option<number>;
  readonly resolution: SlotResolutionKey;
  readonly name: Option.Option<string>;
  readonly blockedBy: Option.Option<string>;
  readonly record: Option.Option<ImportRecord>;
  readonly bindings: ReadonlyArray<SlotBinding>;
}

export interface ImportMap {
  readonly slots: ReadonlyArray<MappedSlot>;
  readonly totals: ImportMapTotals;
}

/**
 * Join the three sources that between them name an import slot, so every fact
 * in the result is traceable to one of them:
 *
 *   - the subject's own import descriptors: which slots exist, which DLL each
 *     belongs to, and the name for every descriptor that still has an
 *     OriginalFirstThunk;
 *   - the module map: every module mapped in the guest and every export it
 *     publishes, so an address can be identified as an export entry point;
 *   - SafeDisc's redirection tables, for the 186 slots whose names the loader
 *     destroyed and whose contents are stubs rather than APIs.
 */
export const buildImportMap = (input: {
  readonly image: PeImage;
  readonly memory: GuestMemory;
  readonly moduleMap: ModuleMap;
  readonly table: RedirectTable;
  readonly declared: ReadonlyArray<DeclaredImportSlot>;
}): Result.Result<ImportMap, GuestMapError> =>
  Result.gen(function* () {
    const { image, memory, moduleMap, table, declared } = input;
    const live = new Map<number, Option.Option<number>>(
      declared.map((s) => [s.va, memory.u32(s.va)]),
    );
    const attached = yield* attachRecords({ declared, table, live });
    const recordBySlotVa = attached.bySlotVa;

    const slots = declared
      .slice()
      .sort((a, b) => a.va - b.va)
      .map((declaration): MappedSlot => {
        const target = live.get(declaration.va) ?? Option.none<number>();
        const record = recordBySlotVa.get(declaration.va);
        const base = {
          va: declaration.va,
          dll: declaration.dll,
          descriptorName: declaration.descriptorName,
          descriptorOrdinal: declaration.descriptorOrdinal,
          target,
        };
        return record === undefined
          ? { ...base, ...answerDirectSlot({ moduleMap, declaration, target }) }
          : { ...base, ...answerRedirectedSlot({ moduleMap, image, declaration, record }) };
      });

    return { slots, totals: tally(slots, attached.moduleIndexToDll) };
  });

// -------------------------------------------------------------- verification

/**
 * Attach each redirected slot's SafeDisc record, and verify the two claims the
 * join rests on.
 *
 * The dispatcher's tables carry a module_index, not a DLL name, so which DLL
 * an index means is established by checking that every record of that index
 * serves a slot the import descriptors assign to one single DLL -- never
 * assumed. And a record is only this slot's record if the slot really holds
 * that record's stub.
 */
interface AttachedRecords {
  readonly bySlotVa: ReadonlyMap<number, ImportRecord>;
  readonly moduleIndexToDll: ReadonlyArray<{ readonly moduleIndex: number; readonly dll: string }>;
}

const attachRecords = (input: {
  readonly declared: ReadonlyArray<DeclaredImportSlot>;
  readonly table: RedirectTable;
  readonly live: ReadonlyMap<number, Option.Option<number>>;
}): Result.Result<AttachedRecords, GuestMapError> => {
  const byVa = new Map(input.declared.map((s) => [s.va, s]));
  const attached = new Map<number, ImportRecord>();
  const dllsByIndex = new Map<number, Set<string>>();
  for (const record of input.table.records) {
    const slot = byVa.get(record.slot);
    if (slot === undefined) {
      return Result.fail(
        new GuestMapError({
          reason: `SafeDisc record ${hex(record.address)} claims slot ${hex(record.slot)}, which is not an IAT slot`,
        }),
      );
    }
    const held = input.live.get(record.slot) ?? Option.none<number>();
    if (Option.isNone(held) || held.value !== record.stub) {
      return Result.fail(
        new GuestMapError({
          reason:
            `slot ${hex(record.slot)} holds ` +
            `${Option.isNone(held) ? 'an unreadable page' : hex(held.value)}` +
            `, not its record's stub ${hex(record.stub)}`,
        }),
      );
    }
    attached.set(slot.va, record);
    const dlls = dllsByIndex.get(record.moduleIndex) ?? new Set<string>();
    dlls.add(slot.dll);
    dllsByIndex.set(record.moduleIndex, dlls);
  }
  for (const [index, dlls] of dllsByIndex) {
    if (dlls.size !== 1) {
      return Result.fail(
        new GuestMapError({
          reason: `module_index ${index} spans several DLLs: ${[...dlls].sort().join(', ')}`,
        }),
      );
    }
  }
  return Result.succeed({
    bySlotVa: attached,
    moduleIndexToDll: [...dllsByIndex.entries()]
      .sort(([a], [b]) => a - b)
      .map(([moduleIndex, dlls]) => ({ moduleIndex, dll: [...dlls][0]! })),
  });
};

// ------------------------------------------------------------- naming a slot

/**
 * The name to publish for an exact export reached from this slot's DLL.
 *
 * Three things can make the raw resolution the wrong name to print, and all
 * three are decided here so no caller repeats the reasoning: a forwarded
 * export resolves to the module that implements it, so the name the importing
 * DLL published is recovered; several exports can share one address, so the
 * descriptor's own name picks between them when it is one of them; and an
 * export with no name at all is written as its ordinal rather than as a
 * missing value.
 */
const apiName = (
  moduleMap: ModuleMap,
  declaration: DeclaredImportSlot,
  resolution: Extract<Resolution, { _tag: 'ExportExact' }>,
): string => {
  const alias = moduleMap.aliasIn(declaration.dll, resolution);
  if (Option.isSome(alias)) return `${declaration.dll}!${alias.value}`;
  if (
    Option.isSome(declaration.descriptorName) &&
    resolution.aliases.includes(declaration.descriptorName.value)
  ) {
    return `${resolution.module}!${declaration.descriptorName.value}`;
  }
  return `${resolution.module}!${Option.getOrElse(resolution.name, () => `#${resolution.ordinal}`)}`;
};

const exportExact = (
  resolution: Option.Option<Resolution>,
): Option.Option<Extract<Resolution, { _tag: 'ExportExact' }>> =>
  Option.isSome(resolution) && resolution.value._tag === 'ExportExact'
    ? Option.some(resolution.value)
    : Option.none();

type SlotAnswer = Pick<
  MappedSlot,
  'resolution' | 'name' | 'blockedBy' | 'record' | 'bindings'
>;

/** A slot that holds a real API address. */
const answerDirectSlot = (input: {
  readonly moduleMap: ModuleMap;
  readonly declaration: DeclaredImportSlot;
  readonly target: Option.Option<number>;
}): SlotAnswer => {
  const empty = { record: Option.none<ImportRecord>(), bindings: [] as ReadonlyArray<SlotBinding> };
  if (Option.isNone(input.target)) {
    return {
      ...empty,
      resolution: 'not-an-export',
      name: Option.none(),
      blockedBy: Option.some(`the page holding slot ${hex(input.declaration.va)} is not resident`),
    };
  }
  const held = input.target.value;
  const resolution = input.moduleMap.resolve(held);
  if (Option.isNone(resolution)) {
    return {
      ...empty,
      resolution: 'not-an-export',
      name: Option.none(),
      blockedBy: Option.some(`${hex8(held)} is not inside any mapped module`),
    };
  }
  const exact = exportExact(resolution);
  if (Option.isNone(exact)) {
    const offset = resolution.value._tag === 'ExportOffset' ? resolution.value.offset : 0;
    return {
      ...empty,
      resolution: 'not-an-export',
      name: Option.none(),
      blockedBy: Option.some(
        `${hex8(held)} is 0x${offset.toString(16)} bytes past ` +
          `${describeResolution(resolution.value)}, not an export entry point`,
      ),
    };
  }
  return {
    ...empty,
    resolution: 'export-exact',
    name: Option.some(apiName(input.moduleMap, input.declaration, exact.value)),
    blockedBy: Option.none(),
  };
};

/** A slot that holds a SafeDisc stub: its answer is per call site. */
const answerRedirectedSlot = (input: {
  readonly moduleMap: ModuleMap;
  readonly image: PeImage;
  readonly declaration: DeclaredImportSlot;
  readonly record: ImportRecord;
}): SlotAnswer => {
  const { moduleMap, image, declaration, record } = input;
  const bindings = record.bindings
    .map((binding): SlotBinding => {
      const resolution = moduleMap.resolve(binding.target);
      const exact = exportExact(resolution);
      const operand = callSiteSlotOperand(image, binding.callSite);
      const evidence: BindingEvidence = Option.isNone(operand)
        ? 'record-entry'
        : operand.value === declaration.va
          ? 'call-operand-verified'
          : 'call-operand-names-another-slot';
      return {
        callSite: binding.callSite,
        target: binding.target,
        bucket: binding.bucket,
        api: Option.map(exact, (r) => apiName(moduleMap, declaration, r)),
        evidence,
        blockedBy: Option.isSome(exact)
          ? Option.none()
          : Option.some(
              Option.isSome(resolution)
                ? `${hex8(binding.target)} is not an export entry point (${describeResolution(resolution.value)})`
                : `${hex8(binding.target)} is in no mapped module`,
            ),
        callOperand:
          Option.isSome(operand) && operand.value !== declaration.va ? operand : Option.none(),
      };
    })
    .sort((a, b) => a.callSite - b.callSite);

  const named = new Set(
    bindings.flatMap((b) => (Option.isSome(b.api) ? [b.api.value] : [])),
  );
  if (bindings.length === 0) {
    const span = bucketSpan(record);
    return {
      record: Option.some(record),
      bindings,
      resolution: 'no-cached-call-site',
      name: Option.none(),
      blockedBy: Option.some(
        'SafeDisc resolves this import per call site and caches the result; this ' +
          `record's ${BUCKET_COUNT}-bucket cache at ${hex8(span.lo)}..${hex8(span.hi)} is ` +
          'empty, so the import was never called before the snapshot and the dump ' +
          'records no name for it',
      ),
    };
  }
  if (named.size === 1) {
    return {
      record: Option.some(record),
      bindings,
      resolution: 'export-exact',
      name: Option.some([...named][0]!),
      blockedBy: Option.none(),
    };
  }
  return {
    record: Option.some(record),
    bindings,
    resolution: 'multiple-apis',
    name: Option.none(),
    blockedBy: Option.none(),
  };
};

// ---------------------------------------------------------------- totals

const tally = (
  slots: ReadonlyArray<MappedSlot>,
  moduleIndexToDll: ReadonlyArray<{ readonly moduleIndex: number; readonly dll: string }>,
): ImportMapTotals => {
  const resolutions: Record<SlotResolutionKey, number> = {
    'export-exact': 0,
    'multiple-apis': 0,
    'no-cached-call-site': 0,
    'not-an-export': 0,
  };
  const evidence: Record<BindingEvidence, number> = {
    'call-operand-verified': 0,
    'record-entry': 0,
    'call-operand-names-another-slot': 0,
  };
  const apis = new Set<string>();
  let bindings = 0;
  let namedBindings = 0;
  let unreadableSlots = 0;
  for (const slot of slots) {
    resolutions[slot.resolution]++;
    if (Option.isNone(slot.target)) unreadableSlots++;
    if (Option.isSome(slot.name)) apis.add(slot.name.value.toLowerCase());
    for (const binding of slot.bindings) {
      bindings++;
      evidence[binding.evidence]++;
      if (Option.isSome(binding.api)) {
        namedBindings++;
        apis.add(binding.api.value.toLowerCase());
      }
    }
  }
  return {
    firstSlot: Math.min(...slots.map((s) => s.va)),
    lastSlot: Math.max(...slots.map((s) => s.va)),
    slots: slots.length,
    unreadableSlots,
    resolutions,
    bindings,
    namedBindings,
    evidence,
    distinctApis: apis.size,
    moduleIndexToDll,
  };
};
