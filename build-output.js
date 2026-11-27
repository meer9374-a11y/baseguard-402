import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname);
const outDir = path.join(root, '.vercel', 'output');
const staticDir = path.join(outDir, 'static');

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(staticDir, { recursive: true });

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

copyDir(path.join(root, 'public'), staticDir);

const functions = [
  ['mcp', 'api/mcp.js'],
  ['api/mcp', 'api/mcp.js'],
  ['api/v1/health', 'api/v1/health.js'],
  ['api/v1/calldata-firewall', 'api/v1/calldata-firewall.js'],
  ['api/v1/swap-preflight', 'api/v1/swap-preflight.js'],
  ['api/v1/token-intel', 'api/v1/token-intel.js']
];

for (const [routePath, handlerRel] of functions) {
  const funcDir = path.join(outDir, 'functions', routePath + '.func');
  fs.mkdirSync(funcDir, { recursive: true });
  copyDir(path.join(root, 'api'), path.join(funcDir, 'api'));
  if (fs.existsSync(path.join(root, 'lib'))) {
    copyDir(path.join(root, 'lib'), path.join(funcDir, 'lib'));
  }
  fs.writeFileSync(
    path.join(funcDir, 'package.json'),
    JSON.stringify({ name: 'baseguard-fn', private: true, type: 'module' }, null, 2)
  );
  fs.writeFileSync(
    path.join(funcDir, '.vc-config.json'),
    JSON.stringify(
      {
        runtime: 'nodejs22.x',
        handler: handlerRel,
        launcherType: 'Nodejs',
        shouldAddHelpers: true
      },
      null,
      2
    )
  );
}

fs.writeFileSync(
  path.join(outDir, 'config.json'),
  JSON.stringify({ version: 3, routes: [{ handle: 'filesystem' }] }, null, 2)
);

console.log('BaseGuard-402 Vercel Build Output v3 ready at:', outDir);
