import preact from '@preact/preset-vite';
import { defineConfig, loadEnv } from 'vite';

// Dev only: /api/* is forwarded to the backend. In production put both behind one origin.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [preact()],
    server: {
      // ponytail: dev only. Lets the ngrok tunnel (bun run tunnel) reach the dev server for Apple's https-only redirect.
      allowedHosts: ['.ngrok-free.dev'],
      proxy: {
        '/api': {
          target: env.VITE_API_URL || 'http://localhost:3000',
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  };
});
