import { defineConfig, mergeConfig } from 'vitest/config';
import packageJson from './package.json';
import viteConfig from './vite.config.ts';

const testConfig = defineConfig({
  test: {
    name: packageJson.name,
    dir: './tests',
    watch: false,
    typecheck: { enabled: true, tsconfig: './tsconfig.test.json' },
  },
});

export default mergeConfig(viteConfig, testConfig);
