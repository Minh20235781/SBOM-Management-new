async function hexDigest(algorithm, bytes) {
  const digest = await crypto.subtle.digest(algorithm, bytes);
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function verifyArtifact(file, component) {
  const bytes = await file.arrayBuffer();
  const algorithm = component.officialHashAlgorithm;
  const computed = await hexDigest(algorithm, bytes);
  const sha256 = algorithm === 'SHA-256' ? computed : await hexDigest('SHA-256', bytes);
  return {
    status: computed === component.officialHash ? 'CHECKSUM_MATCH' : 'CHECKSUM_MISMATCH',
    purl: component.normalizedPurl, file: file.name, size: file.size, sha256, algorithm, computed,
    expected: component.officialHash, source: component.officialRegistry, artifact: component.artifactUrl,
    checkedAt: new Date().toISOString()
  };
}
