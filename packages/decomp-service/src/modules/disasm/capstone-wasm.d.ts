/**
 * capstone-wasm ships its declarations at dist/index.d.ts, but its
 * package.json "exports" map names only the JavaScript, so bundler module
 * resolution never finds them and every import is implicitly `any`.
 *
 * The types are taken FROM those shipped declarations rather than restated
 * here: a hand-written copy of a decoder's surface is a second source of
 * truth that drifts on the next upgrade, silently. A `paths` entry would do
 * the same job for the compiler but is also honoured by the runtime, which
 * then loads the .d.ts as if it were the module.
 */
declare module 'capstone-wasm' {
  type Shipped = typeof import('../../../node_modules/capstone-wasm/dist/index');
  export const loadCapstone: Shipped['loadCapstone'];
  export const Capstone: Shipped['Capstone'];
  export const Const: Shipped['Const'];
  export type Capstone = InstanceType<Shipped['Capstone']>;
}
