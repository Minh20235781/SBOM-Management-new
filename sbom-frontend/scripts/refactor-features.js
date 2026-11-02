#!/usr/bin/env node
import fs from 'fs/promises';
import path from 'path';

function camelToKebab(name) {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/([A-Z])([A-Z][a-z])/g, '$1-$2')
    .toLowerCase();
}

async function ensureDir(dir) {
  try {
    await fs.mkdir(dir, { recursive: true });
  } catch (e) {
    // ignore
  }
}

async function walk(dir, exts = ['.js', '.jsx', '.ts', '.tsx']) {
  const res = [];
  const items = await fs.readdir(dir, { withFileTypes: true });
  for (const it of items) {
    const p = path.join(dir, it.name);
    if (it.isDirectory()) {
      if (it.name === 'node_modules' || it.name === '.git') continue;
      res.push(...await walk(p, exts));
    } else {
      if (exts.includes(path.extname(it.name))) res.push(p);
    }
  }
  return res;
}

async function main() {
  const root = process.cwd();
  const componentsDir = path.join(root, 'src', 'components');

  // Read flat components directory
  const files = await fs.readdir(componentsDir);
  const jsxComponentNames = files
    .filter(f => f.endsWith('.jsx'))
    .map(f => path.basename(f, '.jsx'));

  if (jsxComponentNames.length === 0) {
    console.log('No .jsx components found in src/components. Exiting.');
    return;
  }

  // Map each file to a feature folder based on longest matching component prefix
  const moveMap = {}; // oldFilename -> { componentName, featureDir }

  for (const f of files) {
    const ext = path.extname(f);
    if (!['.js', '.jsx', '.css'].includes(ext)) continue;
    const base = path.basename(f, ext);
    // find longest matching component name
    const matches = jsxComponentNames.filter(n => base.startsWith(n));
    if (matches.length === 0) continue;
    matches.sort((a,b)=>b.length-a.length);
    const comp = matches[0];
    const feature = camelToKebab(comp);
    moveMap[f] = { componentName: comp, featureDir: feature };
  }

  // Perform moves
  const moved = [];
  for (const [filename, info] of Object.entries(moveMap)) {
    const srcPath = path.join(componentsDir, filename);
    const destDir = path.join(componentsDir, info.featureDir);
    await ensureDir(destDir);
    const destPath = path.join(destDir, filename);
    try {
      await fs.rename(srcPath, destPath);
      moved.push({ filename, ...info, destPath });
      console.log(`Moved ${filename} -> ${path.join('src','components',info.featureDir, filename)}`);
    } catch (err) {
      console.error(`Failed to move ${filename}: ${err.message}`);
    }
  }

  // Create barrel index.js in each feature folder
  const features = Array.from(new Set(moved.map(m => m.featureDir)));
  for (const feat of features) {
    const dir = path.join(componentsDir, feat);
    const items = await fs.readdir(dir);
    const exports = [];
    for (const it of items) {
      const ext = path.extname(it);
      const base = path.basename(it, ext);
      if (['.jsx', '.js'].includes(ext)) {
        // export the default as a named export from the file
        const importPath = './' + it;
        exports.push(`export { default as ${base} } from '${importPath}';`);
      }
    }
    if (exports.length > 0) {
      const idxPath = path.join(dir, 'index.js');
      const content = exports.join('\n') + '\n';
      await fs.writeFile(idxPath, content, 'utf8');
      console.log(`Created barrel ${path.join('src','components',feat,'index.js')}`);
    }
  }

  // Build map of original component basenames -> their new absolute file paths
  const nameToNewPath = {};
  for (const m of moved) {
    const abs = path.resolve(m.destPath);
    const base = path.basename(m.filename, path.extname(m.filename));
    nameToNewPath[base] = abs;
  }

  // Update import/require strings across src files
  const srcFiles = await walk(path.join(root, 'src'));
  for (const fpath of srcFiles) {
    let content = await fs.readFile(fpath, 'utf8');
    let updated = false;

    // Replace occurrences like './components/DependencyGraph' or '../components/DependencyGraph' or 'components/DependencyGraph'
    for (const [base, targetAbs] of Object.entries(nameToNewPath)) {
      // regex to find import/require specifiers ending with components/<Base> (optionally with extension)
      const pattern = new RegExp("([\"'`])((?:\.\.?\\/)*components\\/" + base + ")(?:\\.(js|jsx|ts|tsx))?\\1", 'g');
      content = content.replace(pattern, (m, quote, matchPath) => {
        const fileDir = path.dirname(fpath);
        let rel = path.relative(fileDir, targetAbs);
        rel = rel.split(path.sep).join('/');
        if (!rel.startsWith('.')) rel = './' + rel;
        // strip extensions to let bundler resolve, but keep as-is if user wants explicit ext
        rel = rel.replace(/\.(jsx|js|ts|tsx)$/, '');
        updated = true;
        return quote + rel + quote;
      });
    }

    if (updated) {
      await fs.writeFile(fpath, content, 'utf8');
      console.log(`Updated imports in ${path.relative(root, fpath)}`);
    }
  }

  console.log('\nRefactor complete.');
  console.log('If you want to preview changes first, inspect git diff before committing.');
}

main().catch(err => {
  console.error('Refactor failed:', err);
  process.exitCode = 1;
});
