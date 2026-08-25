/** Returns the exported names from static `export { ... }` declarations. */
export const namedExports = (source) => {
  const names = new Set();
  for (const match of source.matchAll(
    /\bexport\s+(?:type\s+)?\{(?<specifiers>[^}]*)\}/gu
  )) {
    for (const specifier of match.groups.specifiers.split(",")) {
      const parts = specifier
        .trim()
        .replace(/^type\s+/u, "")
        .split(/\s+as\s+/u);
      const name = parts.at(-1);
      if (name !== undefined && name !== "") {
        names.add(name);
      }
    }
  }
  return names;
};
