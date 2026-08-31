import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  // Output directly into the directory embedded by the daygle-dns-gui crate.
  build: {
    outDir: 'dist',
    emptyOutDir: true,
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
