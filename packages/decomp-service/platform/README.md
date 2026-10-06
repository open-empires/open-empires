# What the browser build must supply

These are not part of the deliverable. They are the smallest set of
declarations that lets the portable tree be compiled as a CHECK, and by being
the smallest they are also the list of what a real WebAssembly build has to
provide.

The reconstructions are proved under MSVC 6, whose headers are not portable and
are not shipped here. The verification compiles each one with a `string.h`
include prepended, so a source may call `strcpy` without declaring it and still
be proved byte-exact; the portable rendering carries that same include, which
means the build needs a `string.h` that declares it.

`bun src/verify.ts portable-compiles` compiles all 3,322 rendered files against
these, targeting wasm32. Before that include was carried and a hex-literal
lexing trap was defused, 167 of them did not compile -- and nobody knew,
because the tree had never once been compiled.

A real build replaces this directory with wasi-sdk or Emscripten headers. The
point of keeping it is that the check needs no toolchain beyond clang, so it
runs anywhere and cannot quietly stop running.

The functions declared here are exactly those the proved corpus calls. If a new
reconstruction calls something absent, the check fails and names it, which is
how this list stays honest rather than aspirational.

## The one file that still does not compile, and why no rewrite is offered

`sub_0041E740.cpp` fails with `assigning to 'void *' from incompatible type
'int (int)'`. The source declares `extern int __stdcall CB(int);` and a struct
field `void *cb;`, then assigns one to the other. MSVC performs the
function-to-`void *` conversion implicitly; in C++ it is not implicit.

No mechanical rewrite is offered for it, deliberately. Inserting a `(void *)`
cast wherever a bare identifier is assigned would be wrong in exactly the
cases that matter: an assignment whose target is a real function pointer
compiles today and would stop compiling, because `void *` does not convert
back. Getting it right needs to know the declared type of the assignment's
LEFT side, which means type-aware parsing rather than a pattern.

So it wants either a hand-written portable rendering of that one function, or
a converter that carries type information. One file of 3,268 is not the
argument for the second.
