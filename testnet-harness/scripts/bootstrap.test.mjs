// A harness script that imports a module from another package of this repository runs with that
// package's own dependencies: Node resolves the module's bare imports from its nearest
// node_modules, not from this directory's. A clean checkout has only what `run.sh` installs, and
// CI installs more, so a missing install fails a real run while every CI job passes. These tests
// require each such package to be installed by `run.sh` and by the README's standalone setup.
// Only static imports count: they load whenever the script does. A dynamic `import()` is
// conditional (the passkey owner's `../browser`), and `run.sh` installs its package on that
// condition. The scan covers the scripts in this directory and their direct imports; a package
// reached only through another package's own imports is that package's dependency to declare.
//
//   node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPTS = dirname(fileURLToPath(import.meta.url));
const HARNESS = dirname(SCRIPTS);
const ROOT = dirname(HARNESS);

function packageRoot(file) {
  for (let dir = dirname(file); dir.startsWith(ROOT); dir = dirname(dir)) {
    if (existsSync(join(dir, 'package.json'))) return dir;
  }
  return null;
}

/** Repository-relative roots of the other packages that harness scripts statically import from. */
function foreignPackages() {
  const roots = new Set();
  for (const name of readdirSync(SCRIPTS)) {
    if (!name.endsWith('.mjs') || name.endsWith('.test.mjs')) continue;
    const source = readFileSync(join(SCRIPTS, name), 'utf8');
    for (const [, spec] of source.matchAll(/(?:\bfrom|^\s*import)\s*['"](\.{1,2}\/[^'"]+)['"]/gm)) {
      const owner = packageRoot(resolve(SCRIPTS, spec));
      if (owner !== null && owner !== SCRIPTS) roots.add(relative(ROOT, owner));
    }
  }
  return [...roots].sort();
}

test('harness scripts import modules from the wallet package', () => {
  // Guards the scan itself: if it found nothing, the tests below would pass vacuously.
  assert.ok(foreignPackages().includes('wallet'));
});

test('run.sh installs every package whose modules the harness imports', () => {
  const script = readFileSync(join(HARNESS, 'run.sh'), 'utf8');
  for (const pkg of foreignPackages()) {
    // At the start of a line: not commented out, and not inside a conditional block.
    assert.ok(script.split('\n').some((line) => line.startsWith(`npm ci --prefix "$ROOT/${pkg}"`)),
      `run.sh does not install ${pkg} unconditionally`);
  }
});

test('the README standalone setup installs every package whose modules the harness imports', () => {
  const readme = readFileSync(join(HARNESS, 'README.md'), 'utf8');
  for (const pkg of foreignPackages()) {
    assert.ok(readme.includes(`npm ci --prefix ../../${pkg}`), `README standalone setup does not install ${pkg}`);
  }
});
