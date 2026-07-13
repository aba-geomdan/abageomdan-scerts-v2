import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import obfuscator from 'vite-plugin-javascript-obfuscator';

export default defineConfig({
  plugins: [
    react(),
    // 코드 난독화 — 배포 빌드 때만, 내 코드(src)만 처리. 라이브러리는 제외.
    obfuscator({
      include: [/src\/.*\.(js|jsx|ts|tsx)$/],
      exclude: [/node_modules/],
      apply: 'build',
      debugger: false,
      options: {
        compact: true,
        controlFlowFlattening: false,
        deadCodeInjection: false,
        stringArray: true,
        stringArrayThreshold: 0.75,
        stringArrayEncoding: ['base64'],
        identifierNamesGenerator: 'hexadecimal',
        debugProtection: false,
        disableConsoleOutput: false,
        selfDefending: false,
      },
    }),
  ],
  base: '/abageomdan-scerts-v2/',
  build: { outDir: 'dist', sourcemap: false },
});
