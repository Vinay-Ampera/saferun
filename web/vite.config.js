import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev only: the Vite dev server proxies /api to the loopback SafeRun server. In production the SPA is served by
// the SafeRun server itself (same origin, no CORS), so nothing here is a deployment configuration.
export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 5173, proxy: { '/api': 'http://127.0.0.1:8765' } },
  build: { outDir: 'dist', sourcemap: false, assetsInlineLimit: 0 },
  test: { environment: 'jsdom', globals: true, include: ['src/**/*.test.{js,jsx}'], setupFiles: ['src/test-setup.js'] },
})
