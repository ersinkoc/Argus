import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  base: '/ui/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:9090',
        changeOrigin: true,
      },
      '/healthz': {
        target: 'http://localhost:9091',
        changeOrigin: true,
      },
      '/metrics': {
        target: 'http://localhost:9091',
        changeOrigin: true,
      },
      '/ready': {
        target: 'http://localhost:9091',
        changeOrigin: true,
      },
      '/livez': {
        target: 'http://localhost:9091',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    emptyOutDir: true,
  },
})
