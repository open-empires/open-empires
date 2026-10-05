// Does skipping auxiliary records change what the CRT matcher sees?
// Run before and after the refactor; any difference is a real finding.
import { archiveMembers, coffTextSections, coffExternalSymbols } from '../modules/subject/coff';
import { CRT_LIBRARY_PATHS } from '../modules/subject/paths';
import * as coff from './parse';

const lib = Bun.argv[2] ?? CRT_LIBRARY_PATHS[0]!;
const bytes = new Uint8Array(await Bun.file(lib).arrayBuffer());
let oldTotal = 0, newTotal = 0, differing = 0;
for (const m of archiveMembers(bytes)) {
  for (const s of coffTextSections(m.body)) {
    const oldSyms = coffExternalSymbols(m.body, s.index);
    // Same filter, but over the aux-skipping walk.
    const newSyms = coff
      .symbols(m.body)
      .filter(
        (y) =>
          y.sectionNumber === s.index &&
          y.storageClass === coff.StorageClass.External &&
          y.name !== '' &&
          !y.name.startsWith('@'),
      )
      .map((y) => ({ offset: y.value, name: y.name }))
      .sort((a, b) => a.offset - b.offset || (a.name < b.name ? -1 : 1));
    oldTotal += oldSyms.length;
    newTotal += newSyms.length;
    if (JSON.stringify(oldSyms) !== JSON.stringify(newSyms)) {
      differing++;
      if (differing <= 5) {
        const onlyOld = oldSyms.filter((a) => !newSyms.some((b) => b.name === a.name && b.offset === a.offset));
        const onlyNew = newSyms.filter((b) => !oldSyms.some((a) => a.name === b.name && a.offset === b.offset));
        console.log(`  ${m.name} §${s.index}: only-old=${JSON.stringify(onlyOld)} only-new=${JSON.stringify(onlyNew)}`);
      }
    }
  }
}
console.log(`${lib.split('/').pop()}: symbols old=${oldTotal} new=${newTotal}, sections differing=${differing}`);
