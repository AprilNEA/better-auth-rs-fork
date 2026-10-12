export function secondaryStorageInvocation(storage, synchronous) {
  if (synchronous) return storage;
  const backend = { ...storage };
  for (const name of ["get", "set", "delete"]) {
    const invoke = storage[name];
    backend[name] = async function (...args) { return invoke.apply(this, args); };
  }
  return backend;
}
