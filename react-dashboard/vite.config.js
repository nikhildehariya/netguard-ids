import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5174,
    strictPort: true,
    proxy: {
      '/auth': 'http://127.0.0.1:8081',
      '/api': 'http://127.0.0.1:8081',
      '/admin': 'http://127.0.0.1:8081',
      '/predict': 'http://127.0.0.1:8081',
      '/capture': 'http://127.0.0.1:8081',
      '/history': 'http://127.0.0.1:8081',
      '/detections': 'http://127.0.0.1:8081',
      '/stats': 'http://127.0.0.1:8081',
      '/blocked-ips': 'http://127.0.0.1:8081',
      '/blocklist': 'http://127.0.0.1:8081',
      '/network': 'http://127.0.0.1:8081',
      '/reports': 'http://127.0.0.1:8081',
      '/research': 'http://127.0.0.1:8081',
      '/forensics': 'http://127.0.0.1:8081',
      '/assistant': 'http://127.0.0.1:8081',
      '/explain': 'http://127.0.0.1:8081',
      '/health': 'http://127.0.0.1:8081',
      '/threat-intel': 'http://127.0.0.1:8081',
      '/fleet': 'http://127.0.0.1:8081',
      '/soar': 'http://127.0.0.1:8081',
      '/retrain': 'http://127.0.0.1:8081',
      '/sensor': 'http://127.0.0.1:8081',
      '/ws': {
        target: 'ws://127.0.0.1:8081',
        ws: true
      }
    }
  }
})



