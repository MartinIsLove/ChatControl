import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [vue()],
  define: {
    __API_URL__: JSON.stringify('https://server.apernici.it'),
    __WEBSOCKETURL__:JSON.stringify('wss://server.apernici.it')
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  server: {
    https: {
      key: fs.readFileSync(path.resolve(__dirname, './certs/key.pem')),
      cert: fs.readFileSync(path.resolve(__dirname, './certs/cert.pem')),
    },
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  }
})

