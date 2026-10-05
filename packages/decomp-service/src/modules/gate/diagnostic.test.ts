/**
 * A failed compile must report what the COMPILER said.
 *
 * The build log always ends with the shell's own `status=2 size=0` echo, and
 * the diagnostic was taken as its last line -- so every failed compile
 * reported that echo and discarded the `error C2664:` sitting above it. An
 * agent writing a draft that did not compile was told only that it did not
 * compile, and one resorted to `docker exec` against the gate's own container
 * to read the real message.
 */
import { expect, test } from 'bun:test';
import { compilerDiagnostic } from './impl';

const LOG = `Microsoft (R) 32-bit C/C++ Optimizing Compiler Version 12.00.8168 for 80x86
Copyright (C) Microsoft Corp 1984-1998. All rights reserved.

in-ab12cd34.cpp
in-ab12cd34.cpp(42) : error C2664: 'f' : cannot convert parameter 1 from 'int' to 'char *'
in-ab12cd34.cpp(51) : error C2065: 'nope' : undeclared identifier
status=2 size=0`;

test('the compiler error is reported, not the shell status echo', () => {
  const d = compilerDiagnostic(LOG);
  expect(d).toContain('error C2664');
  expect(d).not.toMatch(/^status=/);
});

test('several errors are kept, because the first is often a consequence', () => {
  const d = compilerDiagnostic(LOG);
  expect(d).toContain('error C2664');
  expect(d).toContain('error C2065');
});

test('a fatal error counts as a diagnostic', () => {
  const d = compilerDiagnostic('in.cpp(1) : fatal error C1004: unexpected end of file\nstatus=2 size=0');
  expect(d).toContain('C1004');
});

test('a log with no compiler error still says something', () => {
  // An empty diagnostic is worse than a noisy one: it reads as "no reason".
  const d = compilerDiagnostic('something went wrong in the container\nstatus=2 size=0');
  expect(d.length).toBeGreaterThan(0);
});
