// Bundles src/ into dist/ and copies static assets. Usage: node build.mjs
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, 'dist');

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

await build({
  entryPoints: { background: join(root, 'src/background.ts'), blocked: join(root, 'src/blocked.ts') },
  outdir: dist,
  bundle: true,
  format: 'esm',
  target: 'chrome116',
  minify: false,
  sourcemap: false,
  legalComments: 'none',
  logLevel: 'info',
});

cpSync(join(root, 'static'), dist, { recursive: true });
console.log('extension built into dist/');
