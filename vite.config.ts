import { defineConfig } from 'vitest/config';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  base: './',
  plugins: [viteSingleFile()],
  build: {
    target: 'es2020',
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
