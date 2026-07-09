import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/abageomdan-scerts-v2/',
  build: { outDir: 'dist', sourcemap: false },
});
