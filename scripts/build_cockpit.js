import { readFileSync, writeFileSync } from 'node:fs';

const html = readFileSync('public/index.html', 'utf-8');
const output = `// Auto-generated zero-dependency static fallback for serverless environments\nexport const COCKPIT_HTML: string = ${JSON.stringify(html)};\n`;
writeFileSync('src/cockpit_html.ts', output);
