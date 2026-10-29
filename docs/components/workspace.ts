// Workspace metadata, read from the root manifest every crate inherits it
// from, so the site follows `just release` without edits.
import cargo from "../../Cargo.toml?raw";

const field = (key: string) =>
  cargo.match(new RegExp(`^${key} = "(?<value>[^"]+)"`, "mu"))?.groups?.value;

export const version = field("version");
export const license = field("license");
export const rustVersion = field("rust-version");
