import { defineConfig } from 'vitest/config';
import packageJson from './package.json';

export default defineConfig({
  test: {
    name: packageJson.name,
    dir: './tests',
    watch: false,
    typecheck: { enabled: true, tsconfig: './tsconfig.test.json' },
    environment: 'jsdom',
    setupFiles: ['./tests/setup-idb.ts'],
  },
});
