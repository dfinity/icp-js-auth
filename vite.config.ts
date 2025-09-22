import { tanstackViteConfig } from '@tanstack/config/vite';

export default tanstackViteConfig({
  entry: ['./src/index.ts', './src/client/index.ts'],
  srcDir: './src',
  outDir: './dist',
  tsconfigPath: './tsconfig.lib.json',
  cjs: false,
});
