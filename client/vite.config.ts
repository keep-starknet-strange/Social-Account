import preact from '@preact/preset-vite';
import { defineConfig, loadEnv } from 'vite';

// Dev only: /api/* is forwarded to the backend. In production put both behind one origin.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [preact()],
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
