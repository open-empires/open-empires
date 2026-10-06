/*
 * The Microsoft-only spellings the proved sources contain, declared so a
 * conforming compiler accepts them.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The sources in the database are the VERIFICATION artifact: they are written
 * to compile under MSVC 6 and reproduce the subject's bytes, and that is the
 * only thing they have to do. Several of them therefore use spellings that
 * only Microsoft's compiler accepts. The portable tree is generated from
 * them, so the generator has to bridge the difference -- and the honest place
 * to bridge it is a header, not an edit to the source, because editing the
 * source would mean the thing that was proved and the thing that is built are
 * no longer the same text.
 *
 * Each declaration here is a measured failure from
 * `bun src/verify.ts portable-compiles`, not an anticipated one.
 */
#ifndef OE_MSVC_H
#define OE_MSVC_H

/* MSVC's 64-bit integer spelling. One source names it; nothing defines it off
 * Microsoft's compiler. */
typedef long long __int64;
typedef unsigned long long __uint64;

/* `__forceinline` is MSVC's spelling of an inlining demand. Rendered as a
 * request rather than a demand: the browser build's code generator is not the
 * one the bytes were proved against, so forcing its hand would be a claim
 * nothing here can support. */
#ifndef __forceinline
#define __forceinline inline
#endif

/* Calling conventions. They decide the x86 byte layout and therefore matter
 * enormously to the proof -- and mean nothing in WebAssembly, which has one
 * convention. They are stripped by the generator rather than defined away
 * here; these remain only for a source that spells one somewhere the
 * generator's pattern does not reach. */
#ifndef __cdecl
#define __cdecl
#endif
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __fastcall
#define __fastcall
#endif

#endif /* OE_MSVC_H */
