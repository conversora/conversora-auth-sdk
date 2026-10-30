import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

async function resolveEsbuild() {
  try {
    return require('esbuild');
  } catch {
    // Search monorepo root
    const monorepoRoot = path.resolve(__dirname, '../../');
    const rootRequire = createRequire(path.join(monorepoRoot, 'package.json'));
    try {
      return rootRequire('esbuild');
    } catch {
      return require('../../node_modules/.pnpm/esbuild@0.28.2/node_modules/esbuild');
    }
  }
}

async function build() {
  console.log('📦 Building @conversora/auth-client...');
  const esbuild = await resolveEsbuild();

  // 1. Build ESM & CJS with esbuild
  await Promise.all([
    esbuild.build({
      entryPoints: {
        index: path.join(__dirname, 'src/index.ts'),
        'react/index': path.join(__dirname, 'src/react/index.ts'),
      },
      outdir: path.join(__dirname, 'dist'),
      bundle: true,
      platform: 'neutral',
      format: 'esm',
      target: 'es2022',
      outExtension: { '.js': '.mjs' },
      external: ['react', 'react-dom'],
      sourcemap: true,
    }),
    esbuild.build({
      entryPoints: {
        index: path.join(__dirname, 'src/index.ts'),
        'react/index': path.join(__dirname, 'src/react/index.ts'),
      },
      outdir: path.join(__dirname, 'dist'),
      bundle: true,
      platform: 'neutral',
      format: 'cjs',
      target: 'es2022',
      outExtension: { '.js': '.cjs' },
      external: ['react', 'react-dom'],
      sourcemap: true,
    }),
  ]);

  // 2. Emit TypeScript declaration types
  execSync('npx tsc -p tsconfig.build.json', { cwd: __dirname, stdio: 'inherit' });

  console.log('✅ Build complete! dist/ ready for GitHub distribution.');
}

build().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
