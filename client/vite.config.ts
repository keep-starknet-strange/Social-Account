import preact from '@preact/preset-vite';
import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv } from 'vite';

// Dev only: /api/* is forwarded to the backend. In production put both behind one origin.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [preact()],
    // starkzap's bridge and privacy modules import optional peers (ethers, tongo) that this app
    // does not install. Vite's default stand-in throws when loaded, so point them at an empty module.
    resolve: {
      alias: {
        ethers: fileURLToPath(
          new URL('./src/stubs/optional-peer.cjs', import.meta.url),
        ),
        '@fatsolutions/tongo-sdk': fileURLToPath(
          new URL('./src/stubs/optional-peer.cjs', import.meta.url),
        ),
      },
    },
    server: {
      proxy: {
        '/api': {
          target: env.VITE_API_URL || 'http://localhost:3000',
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  };
});
