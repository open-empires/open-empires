/**
 * The rules that decide whether a string names its containing function.
 *
 * Pure, so this is the one part of the name recovery that can be held to its
 * rules by a test rather than by a run over the subject. The rule that matters
 * most is the refusal: a string that is the tag at two places names neither,
 * and a version of this that skipped the check would write a wrong name into
 * `functions.name` where nothing downstream could catch it.
 */
import { expect, test } from 'bun:test';
import { Option } from 'effect';
import { attribute } from './attribution';
import { immediates } from './references';
import { classOfName, dataStrings } from './strings';
import { SECTION_EXECUTABLE } from '../subject/interface';
import type { ReferenceRole, StringReference } from './interface';

const LOCK = 0x465ba0;
const UNLOCK = 0x465c20;
const ACQUIRE = 0x465c60;

const ref = (input: {
  readonly site: number;
  readonly text: string;
  readonly fn: number | null;
  readonly consumer?: number;
  readonly role?: ReferenceRole;
  readonly memberOffset?: number;
}): StringReference => ({
  site: input.site,
  stringVa: 0x670000,
  text: input.text,
  mnemonic: 'push',
  anchored: input.fn !== null,
  containingFunction: Option.fromNullishOr(input.fn),
  consumer: Option.fromNullishOr(input.consumer ?? null),
  consumedAt: Option.some(input.site + 5),
  argIndex: Option.some(0),
  surface:
    input.memberOffset === undefined
      ? Option.none()
      : Option.some({
          at: input.site - 3,
          memberOffset: input.memberOffset,
          instruction: `mov ecx, dword ptr [esi + 0x${input.memberOffset.toString(16)}]`,
        }),
  role:
    input.role ??
    (input.consumer === ACQUIRE ? 'self-named-other' : 'lock-tag'),
});

test('one tag from one place names the containing function', () => {
  const { names, withheld } = attribute([
    ref({ site: 0x4486b7, text: 'diam_map::draw', fn: 0x448590, consumer: LOCK, memberOffset: 0x20 }),
    ref({ site: 0x4486d2, text: 'diam_map::draw', fn: 0x448590, consumer: UNLOCK, memberOffset: 0x20 }),
  ]);
  expect(withheld).toEqual([]);
  expect(names).toHaveLength(1);
  expect(names[0]!.name).toBe('diam_map::draw');
  expect(names[0]!.confidence).toBe('lock-tag');
  expect(Option.getOrNull(names[0]!.className)).toBe('diam_map');
  expect(names[0]!.refSites).toEqual([0x4486b7, 0x4486d2]);
  expect(names[0]!.surfaceMemberOffsets).toEqual([0x20]);
});

test('a reference the patterns do not recognise names nothing', () => {
  const { names, withheld } = attribute([
    ref({ site: 0x437210, text: 'scr_game::draw', fn: 0x437200, consumer: 0x428190, role: 'referenced-only' }),
  ]);
  expect(names).toEqual([]);
  expect(withheld).toEqual([]);
});

test('a tag pushed from two functions is withheld for both, naming the places', () => {
  const { names, withheld } = attribute([
    ref({ site: 0x4c0467, text: 'pnl_scbr::draw', fn: 0x4c0430, consumer: LOCK }),
    ref({ site: 0x4c05e1, text: 'pnl_scbr::draw', fn: 0x4c05c0, consumer: LOCK }),
  ]);
  expect(names).toEqual([]);
  expect(withheld.map((w) => w.va)).toEqual([0x4c0430, 0x4c05c0]);
  for (const held of withheld) {
    expect(held.candidates).toEqual(['pnl_scbr::draw']);
    expect(held.reason).toBe(
      'the same tag is pushed from 2 places (004C0430, 004C05C0), so it cannot ' +
        'be shown to name this one',
    );
  }
});

test('an unattributed region is a place, so it withholds the name it would have given', () => {
  const { names, withheld } = attribute([
    ref({ site: 0x448f5d, text: 'diam_map::draw_objects', fn: 0x448f50, consumer: LOCK }),
    ref({ site: 0x5db5f7, text: 'diam_map::draw_objects', fn: null, consumer: LOCK }),
  ]);
  expect(names).toEqual([]);
  expect(withheld).toHaveLength(1);
  expect(withheld[0]!.reason).toBe(
    'the same tag is pushed from 2 places (00448F50, an unattributed .text ' +
      'region), so it cannot be shown to name this one',
  );
});

test('every site in unattributed regions is ONE place, not one each', () => {
  const { withheld } = attribute([
    ref({ site: 0x5befc3, text: 'tpnl_obj::draw_item', fn: 0x5bef90, consumer: LOCK }),
    ref({ site: 0x5bf0df, text: 'tpnl_obj::draw_item', fn: 0x5bf0a0, consumer: LOCK }),
    ref({ site: 0x5dc100, text: 'tpnl_obj::draw_item', fn: null, consumer: LOCK }),
    ref({ site: 0x5dc200, text: 'tpnl_obj::draw_item', fn: null, consumer: UNLOCK }),
  ]);
  expect(withheld[0]!.reason).toContain('from 3 places');
});

test('a function pushing several tags is withheld, and that reason wins over the other', () => {
  const { names, withheld } = attribute([
    // 0x5BF650 is both: it carries three tags, and one of them is also the tag
    // at 0x5BF190. What its reader needs told is that its own body has three.
    ref({ site: 0x5bf735, text: 'tpnl_obj::draw_research', fn: 0x5bf650, consumer: LOCK }),
    ref({ site: 0x5bf8fb, text: 'tpnl_obj::draw_research2', fn: 0x5bf650, consumer: LOCK }),
    ref({ site: 0x5bfa20, text: 'tpnl_obj::draw_research3', fn: 0x5bf650, consumer: LOCK }),
    ref({ site: 0x5bf42f, text: 'tpnl_obj::draw_research', fn: 0x5bf190, consumer: LOCK }),
  ]);
  expect(names).toEqual([]);
  const held = withheld.find((w) => w.va === 0x5bf650)!;
  expect(held.candidates).toEqual([
    'tpnl_obj::draw_research',
    'tpnl_obj::draw_research2',
    'tpnl_obj::draw_research3',
  ]);
  expect(held.reason).toContain('more than one distinct tag');
  expect(withheld.find((w) => w.va === 0x5bf190)!.reason).toContain('from 2 places');
});

test('the lock pair wins where both pairs carry the same tag', () => {
  const { names } = attribute([
    ref({ site: 0x100, text: 'pnl_msg::draw', fn: 0x90, consumer: ACQUIRE }),
    ref({ site: 0x120, text: 'pnl_msg::draw', fn: 0x90, consumer: LOCK }),
  ]);
  expect(names[0]!.confidence).toBe('lock-tag');
});

test('the second pair alone is a weaker confidence, not a refusal', () => {
  const { names } = attribute([
    ref({ site: 0x100, text: 'pnl_txt::draw', fn: 0x90, consumer: ACQUIRE }),
  ]);
  expect(names[0]!.confidence).toBe('self-named-other');
});

test('an unqualified name carries no class', () => {
  const { names } = attribute([
    ref({ site: 0x100, text: 'take_snapshot', fn: 0x467ba0, consumer: LOCK }),
  ]);
  expect(Option.isNone(names[0]!.className)).toBe(true);
  expect(Option.isNone(classOfName('take_snapshot'))).toBe(true);
  expect(Option.getOrNull(classOfName('view::draw_view'))).toBe('view');
});

test('a bracketed literal is a displacement, not an immediate', () => {
  // `mov eax, dword ptr [0x66b0fc]` READS four bytes of the string; counting
  // it would turn every global read of a string into a name reference.
  expect(immediates('eax, dword ptr [0x66b0fc]')).toEqual([]);
  expect(immediates('0x670454')).toEqual([0x670454]);
  expect(immediates('dword ptr [esi], 0x63aa3c')).toEqual([0x63aa3c]);
  expect(immediates('dword ptr [ebp + 8], 0x63fcdc')).toEqual([0x63fcdc]);
});

const strings = () => {
  const bytes = new Uint8Array(0x200);
  const put = (offset: number, text: string) => {
    for (let i = 0; i < text.length; i += 1) bytes[offset + i] = text.charCodeAt(i);
    bytes[offset + text.length] = 0;
  };
  put(0x100, 'diam_map::draw');
  put(0x120, 'LOGDIR:');
  put(0x130, 'Ok');
  put(0x140, 'has space');
  put(0x150, '9leading');
  put(0x010, 'in_the_code');
  return dataStrings({
    bytes,
    sections: [
      {
        name: '.text', va: 0x401000, virtualSize: 0x100, rawOffset: 0, rawSize: 0x100,
        characteristics: SECTION_EXECUTABLE,
      },
      {
        name: '.data', va: 0x600000, virtualSize: 0x100, rawOffset: 0x100, rawSize: 0x100,
        characteristics: 0,
      },
    ],
    textLo: 0x401000,
    textHi: 0x401100,
  });
};

test('an identifier-shaped string is read, whether or not it is qualified', () => {
  const s = strings();
  expect(Option.getOrNull(s.at(0x600000))).toBe('diam_map::draw');
  // A single colon is kept: LOGDIR: and LOGNAME: are real strings, and
  // excluding them would silently shorten the vocabulary.
  expect(Option.getOrNull(s.at(0x600020))).toBe('LOGDIR:');
});

test('what is not a name is absent, not a short or mangled one', () => {
  const s = strings();
  expect(Option.isNone(s.at(0x600030))).toBe(true); // two characters
  expect(Option.isNone(s.at(0x600040))).toBe(true); // a space
  expect(Option.isNone(s.at(0x600050))).toBe(true); // leading digit
  expect(Option.isNone(s.at(0x700000))).toBe(true); // in no section
});

test('a target inside the executable span is not a string, whatever the bytes say', () => {
  // A pushed address in .text is a function pointer. Reading it as text is how
  // a jump table becomes vocabulary.
  expect(Option.isNone(strings().at(0x401010))).toBe(true);
});
