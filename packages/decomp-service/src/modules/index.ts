import { interfaces } from 'effective-modules';
import type { IDb } from './db/interface';
import type { IGate } from './gate/interface';
import type { IDisasm } from './disasm/interface';
import type { IRegistry } from './registry/interface';
import type { IWork } from './work/interface';
import type { IMetrics } from './metrics/interface';
import type { ISubject } from './subject/interface';
import type { ILegacy } from './legacy/interface';
import type { ICompose } from './compose/interface';
import type { IPortable } from './portable/interface';
import type { IReloc } from './reloc/interface';
import type { INames } from './names/interface';
import type { IImportNames } from './import-names/interface';

/**
 * The decompilation service.
 *
 * It owns the database, the compiler gate, and the work queue. Agents hold no
 * files and no locks; they call this service. The Python tooling it replaces
 * decided verdicts in a script and left the database downstream of JSON --
 * which is how proofs outlived the compilers that made them.
 */
export enum Modules {
  Db = 'Db',
  Subject = 'Subject',
  Disasm = 'Disasm',
  Gate = 'Gate',
  Work = 'Work',
  Registry = 'Registry',
  Metrics = 'Metrics',
  /** Assemble the whole executable span from the reconstructions and diff it
   *  against the subject. The only proof that says they COMPOSE. */
  Compose = 'Compose',
  /** Derive the portable C++ tree the WebAssembly build needs from the MSVC
   *  reconstructions, which stay the verification artifact. */
  Portable = 'Portable',
  /** Verify that every relocation field in a reconstruction points at a
   *  declared symbol, which the masked comparison cannot. */
  Reloc = 'Reloc',
  /** Read the original function names back out of the subject's own strings,
   *  which is the only source of them this binary still carries. */
  Names = 'Names',
  /** Name import slots from the relocation tables of the libraries whose
   *  objects are already identified in the image. The library states which
   *  symbol each call site targets, so no name is inferred from a call shape. */
  ImportNames = 'ImportNames',
  /** The one-time move of the Python tooling's files into this database. Not
   *  part of serving; it runs once, from `src/import.ts`. */
  Legacy = 'Legacy',
}

export const modules = interfaces<
  Modules,
  {
    Db: IDb; Subject: ISubject; Disasm: IDisasm; Gate: IGate;
    Work: IWork; Registry: IRegistry; Metrics: IMetrics; Legacy: ILegacy;
    Compose: ICompose; Portable: IPortable; Reloc: IReloc; Names: INames;
    ImportNames: IImportNames;
  }
>(Modules);
