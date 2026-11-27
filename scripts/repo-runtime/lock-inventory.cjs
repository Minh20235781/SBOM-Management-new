// Preserve the locked versions when npm rejects an inconsistent dependency tree.
const fs = require('node:fs');
const lock = JSON.parse(fs.readFileSync('package-lock.json', 'utf8'));
const components = [];
for (const [location, pkg] of Object.entries(lock.packages)) {
  if (!location || pkg.link || !pkg.version) continue;
  const name = pkg.name || location.split('node_modules/').pop();
  const purl = 'pkg:npm/' + name.split('/').map(encodeURIComponent).join('/') + '@' + encodeURIComponent(pkg.version);
  components.push({type:'library', name, version:pkg.version, purl, 'bom-ref':location});
}
const metadata = {
  component:{type:'application',name:lock.name,version:lock.version},
  properties:[{name:'sbom:lockfileStatus', value:'ESBOMPROBLEMS'}]
};
console.log(JSON.stringify({bomFormat:'CycloneDX',specVersion:'1.6',version:1,metadata,components}));
