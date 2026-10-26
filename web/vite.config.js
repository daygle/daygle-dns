import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  // Output directly into the directory embedded by the daygle-dns-gui crate.
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The console is one bundle embedded in the server binary and loaded
    // once, usually over the local network: splitting it would only add
    // requests, so a bundle past Vite's 500 kB default is expected.
    chunkSizeWarningLimit: 1024,
  },
  server: {
    proxy: {
      // During development, forward API calls to the running server.
      '/api': {
        target: 'http://127.0.0.1:5380',
        changeOrigin: true,
      },
    },
  },
});
