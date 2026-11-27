export function projectFromUrl(value) {
  const match = /^https:\/\/github\.com\/([\w-]+)\/([\w.-]+)(?:\/tree\/([\w.-]+)((?:\/[\w.-]+)*))?\/?$/i.exec(String(value).trim());
  if (!match) return null;
  const [, owner, repository, branch = '', subpath = ''] = match;
  const name = repository.replace(/\.git$/i, '');
  if (![owner,name,...[branch,...subpath.split('/')].filter(Boolean)].every(part => /^[\w][\w.-]*$/.test(part))) return null;
  return { repo: owner + '/' + name, branch, directory: subpath.slice(1) || '.' };
}
