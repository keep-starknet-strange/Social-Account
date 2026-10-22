// Vite alias target for garaga's top-level `fs` and `crypto` imports. Those are only used by its
// Node-only helpers (reading proof files); the RSA hint builder never touches them.
export function createHash(): never {
  throw new Error('node crypto is not available in the browser');
}
export default {};
