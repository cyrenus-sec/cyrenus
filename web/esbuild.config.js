const esbuild = require('esbuild');

esbuild.build({
    entryPoints: ['src/app.ts'],
    bundle: true,
    outfile: 'dist/app.js',
    minify: true,
    sourcemap: false,
    format: 'iife',
    target: ['es2020'],
}).catch(() => process.exit(1));
