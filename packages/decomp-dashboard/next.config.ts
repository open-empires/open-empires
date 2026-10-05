import type { NextConfig } from 'next';

const config: NextConfig = {
  // node:sqlite is a Node builtin (Node 22+); keep it out of the bundle.
  serverExternalPackages: [],
  env: {
    // The Python collector owns this file; the dashboard only ever reads it.
    PROGRESS_DB: process.env.PROGRESS_DB ?? '../aoe2-in-browser/work/progress.db',
  },
};

export default config;
