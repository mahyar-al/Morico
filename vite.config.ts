import fs from 'fs';
import path from 'path';
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

/**
 * Exclude runtime uploads & internal design/prompt artifacts from the production Vite dist output (C4).
 */
function excludeRuntimePublicDirs(): Plugin {
  return {
    name: 'exclude-runtime-public-dirs',
    apply: 'build',
    closeBundle() {
      const distDir = path.resolve(process.cwd(), 'dist');
      for (const rel of ['uploads', path.join('assets', 'aistudio')]) {
        const target = path.join(distDir, rel);
        if (fs.existsSync(target)) {
          fs.rmSync(target, { recursive: true, force: true });
        }
      }
    }
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), excludeRuntimePublicDirs()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    allowedHosts: true
  }
});
