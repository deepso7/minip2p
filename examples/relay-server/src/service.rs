use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, ArgGroup, Command as ClapCommand, value_parser};
use minip2p::{Ed25519Keypair, PeerId};
use minip2p_example_common::encode_key_file;
#[cfg(unix)]
use minip2p_example_common::read_keypair_owned_by;

use crate::{cli, config};

const SERVICE_NAME: &str = "minip2p-relay";
const SERVICE_USER: &str = "minip2p-relay";
const STATE_DIR: &str = "/var/lib/minip2p-relay";
const IDENTITY_PATH: &str = "/var/lib/minip2p-relay/identity.key";
const MESH_KEY_PATH: &str = "/var/lib/minip2p-relay/mesh.key";
const CONFIG_DIR: &str = "/etc/minip2p-relay";
const CONFIG_PATH: &str = "/etc/minip2p-relay/relay.toml";
const DEFAULT_MESH_PORT: u16 = 19877;
const IDENTITY_STAGING_DIR: &str = "/var/lib";
const EXECUTABLE_PATH: &str = "/usr/local/bin/minip2p-relay";
const UNIT_PATH: &str = "/etc/systemd/system/minip2p-relay.service";
const ENABLED_UNIT_PATH: &str = "/etc/systemd/system/multi-user.target.wants/minip2p-relay.service";
const CHOWN: &str = "/usr/bin/chown";
const GETENT: &str = "/usr/bin/getent";
const GROUPADD: &str = "/usr/sbin/groupadd";
const ID: &str = "/usr/bin/id";
const INSTALL: &str = "/usr/bin/install";
const JOURNALCTL: &str = "/usr/bin/journalctl";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const USERADD: &str = "/usr/sbin/useradd";

pub fn run(args: impl IntoIterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let matches = match command()
        .try_get_matches_from(std::iter::once("minip2p-relay service".to_string()).chain(args))
    {
        Ok(matches) => matches,
        Err(error) => error.exit(),
    };

    match matches.subcommand() {
        Some(("install", matches)) => {
            let import_key = matches.get_one::<String>("import-key").map(Path::new);
            let text;
            let source = match (
                matches.get_one::<String>("hostname"),
                matches.get_one::<PathBuf>("config"),
            ) {
                (Some(hostname), None) => {
                    config::validate_hostname(hostname)?;
                    Source::Hostname(hostname)
                }
                (None, Some(path)) => {
                    text = fs::read_to_string(path).map_err(|error| {
                        format!("cannot read config {}: {error}", path.display())
                    })?;
                    // Checked now, so a bad file fails before sudo matters.
                    prepare_config(Source::File(&text), None)
                        .map_err(|error| format!("config {}: {error}", path.display()))?;
                    Source::File(&text)
                }
                _ => return Err("pass --hostname or --config".into()),
            };
            install(source, import_key)
        }
        Some(("status", _)) => {
            require_linux()?;
            run_status(SYSTEMCTL, ["status", "--no-pager", SERVICE_NAME])
        }
        Some(("logs", _)) => {
            require_linux()?;
            run_status(JOURNALCTL, ["-u", SERVICE_NAME, "-f"])
        }
        Some(("restart", _)) => {
            require_linux()?;
            require_root()?;
            run_status(SYSTEMCTL, ["restart", SERVICE_NAME])
        }
        Some(("uninstall", _)) => uninstall(),
        _ => Err("a service subcommand is required".into()),
    }
}

/// Where the installed config comes from.
#[derive(Clone, Copy)]
enum Source<'a> {
    /// `--hostname`: a minimal config, or the existing one if it names the
    /// same hostname.
    Hostname(&'a str),
    /// `--config`: this file's text, replacing any existing config.
    File(&'a str),
}

/// The config `service install` writes to [`CONFIG_PATH`].
#[derive(Debug)]
struct Prepared {
    text: String,
    options: cli::Options,
}

/// Builds the config text the service runs with, given the config already
/// installed (if any): fills in the service's key paths and checks the
/// result as the relay would, so a bad config never replaces a working one.
fn prepare_config(source: Source<'_>, existing: Option<&str>) -> Result<Prepared, String> {
    let text = match (source, existing) {
        (Source::Hostname(hostname), None) => format!("hostname = \"{hostname}\"\n"),
        (Source::Hostname(hostname), Some(existing)) => {
            let installed =
                config::File::parse(existing).map_err(|error| format!("{CONFIG_PATH}: {error}"))?;
            if installed.hostname.as_deref() != Some(hostname) {
                return Err(format!(
                    "{CONFIG_PATH} names hostname {:?}, not {hostname:?}; edit it and run `minip2p-relay service restart`, or pass --config",
                    installed.hostname.unwrap_or_default()
                ));
            }
            existing.to_owned()
        }
        (Source::File(text), _) => text.to_owned(),
    };
    let text = fill_key_paths(text)?;
    let file = config::File::parse(&text)?;
    // The CLI's default is an ephemeral key, and another path would bypass
    // `--import-key`'s refusal to replace the service identity. The exact
    // spelling matters: `Path` equality ignores a trailing slash, `open` does not.
    if file.key.as_deref().map(Path::as_os_str) != Some(OsStr::new(IDENTITY_PATH)) {
        return Err(format!(
            "key must be {IDENTITY_PATH:?}, the service identity; use --import-key to install another key there"
        ));
    }
    if let Some(mesh) = &file.mesh
        && mesh.key.as_deref().map(Path::as_os_str) != Some(OsStr::new(MESH_KEY_PATH))
    {
        return Err(format!(
            "[mesh] key must be {MESH_KEY_PATH:?}, the service's backbone key"
        ));
    }
    // The unit runs from an unspecified directory.
    if let Some(webtransport) = &file.webtransport
        && [&webtransport.cert, &webtransport.key]
            .into_iter()
            .flatten()
            .any(|path| !path.is_absolute())
    {
        return Err("[webtransport] cert and key must be absolute paths".into());
    }
    let options = file.options()?;
    if let Some(mesh) = &options.mesh
        && mesh.listen.iter().any(|bind| bind.port() == 0)
    {
        return Err(
            "[mesh] listen port 0 picks a new port on every start, so other members can't list this node; set a fixed port"
                .into(),
        );
    }
    Ok(Prepared { text, options })
}

/// Adds `key` and `[mesh] key` with the service's paths when the config
/// leaves them out, keeping the operator's formatting and comments.
fn fill_key_paths(mut text: String) -> Result<String, String> {
    let file = config::File::parse(&text)?;
    if file.mesh.as_ref().is_some_and(|mesh| mesh.key.is_none()) {
        let line = format!("key = \"{MESH_KEY_PATH}\"\n");
        let mut filled = String::with_capacity(text.len() + line.len() + 1);
        let mut inserted = false;
        for current in text.split_inclusive('\n') {
            filled.push_str(current);
            if !inserted && current.split('#').next().map(str::trim) == Some("[mesh]") {
                if !current.ends_with('\n') {
                    filled.push('\n');
                }
                filled.push_str(&line);
                inserted = true;
            }
        }
        if !inserted {
            return Err(format!("add {line:?} to [mesh]"));
        }
        text = filled;
    }
    // Top-level keys precede every table, so the start is always the root.
    if file.key.is_none() {
        text.insert_str(0, &format!("key = \"{IDENTITY_PATH}\"\n"));
    }
    Ok(text)
}

/// The `mesh_member_candidate=` addresses for this node: one per configured
/// backbone bind, or per default bind when none are configured.
fn mesh_member_candidates(listen: &[SocketAddr], backbone: &PeerId) -> Vec<String> {
    let defaults: [SocketAddr; 2] = [
        SocketAddr::from(([0, 0, 0, 0], DEFAULT_MESH_PORT)),
        SocketAddr::from(([0_u16; 8], DEFAULT_MESH_PORT)),
    ];
    let binds = if listen.is_empty() {
        &defaults[..]
    } else {
        listen
    };
    binds
        .iter()
        .map(|bind| {
            let family = if bind.is_ipv4() { "ip4" } else { "ip6" };
            format!(
                "/{family}/{}/udp/{}/quic-v1/p2p/{backbone}",
                bind.ip(),
                bind.port()
            )
        })
        .collect()
}

/// Quotes one ExecStart path for systemd, naming `what` in errors. `%` and
/// `$` are doubled, because systemd expands specifiers and variables even
/// inside quotes.
fn quoted(path: &Path, what: &str) -> Result<String, Box<dyn Error>> {
    let path = path
        .to_str()
        .ok_or_else(|| format!("the {what} path is not valid UTF-8"))?;
    if path.chars().any(char::is_control) {
        return Err(format!("the {what} path contains a control character").into());
    }
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

/// The unit never changes with the relay's options: they live in
/// [`CONFIG_PATH`].
fn unit_file(executable: &Path) -> Result<String, Box<dyn Error>> {
    let executable = quoted(executable, "relay executable")?;
    Ok(format!(
        "[Unit]\n\
Description=minip2p circuit relay\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
User=minip2p-relay\n\
Group=minip2p-relay\n\
ExecStart={executable} --config {CONFIG_PATH}\n\
Restart=on-failure\n\
RestartSec=5\n\
StandardInput=null\n\
UMask=0077\n\
NoNewPrivileges=true\n\
PrivateTmp=true\n\
ProtectHome=true\n\
ProtectSystem=strict\n\
ReadWritePaths=/var/lib/minip2p-relay\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n"
    ))
}

fn install(source: Source<'_>, import_key: Option<&Path>) -> Result<(), Box<dyn Error>> {
    require_linux()?;
    require_root()?;
    let existing = match source {
        Source::File(_) => None,
        Source::Hostname(_) => match fs::read_to_string(CONFIG_PATH) {
            Ok(text) => Some(text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("cannot read {CONFIG_PATH}: {error}").into()),
        },
    };
    // Built first, so a rejected config fails before anything is installed.
    let prepared = prepare_config(source, existing.as_deref())?;
    let unit = unit_file(Path::new(EXECUTABLE_PATH))?;
    let imported_identity = import_key.map(read_import_identity).transpose()?;
    if imported_identity.is_some() && Path::new(IDENTITY_PATH).exists() {
        return Err(format!(
            "refusing to replace existing identity at {IDENTITY_PATH}; omit --import-key"
        )
        .into());
    }

    if !group_exists(SERVICE_USER)? {
        run_status(GROUPADD, ["--system", SERVICE_USER])?;
    }
    if !user_exists(SERVICE_USER)? {
        run_status(
            USERADD,
            [
                "--system",
                "--gid",
                SERVICE_USER,
                "--home",
                STATE_DIR,
                "--shell",
                "/usr/sbin/nologin",
                SERVICE_USER,
            ],
        )?;
    }
    run_status(
        INSTALL,
        [
            "-d",
            "-m",
            "0700",
            "-o",
            SERVICE_USER,
            "-g",
            SERVICE_USER,
            STATE_DIR,
        ],
    )?;

    install_executable()?;
    if let Some(identity) = imported_identity {
        install_key(&identity, Path::new(IDENTITY_PATH))?;
    }
    let candidates = match &prepared.options.mesh {
        Some(mesh) => mesh_member_candidates(&mesh.listen, &ensure_backbone_key(service_uid()?)?),
        None => Vec::new(),
    };
    run_status(
        INSTALL,
        [
            "-d",
            "-m",
            "0750",
            "-o",
            "root",
            "-g",
            SERVICE_USER,
            CONFIG_DIR,
        ],
    )?;
    write_atomically(
        Path::new(CONFIG_PATH),
        &prepared.text,
        0o640,
        Some(&format!("root:{SERVICE_USER}")),
    )?;
    write_atomically(Path::new(UNIT_PATH), &unit, 0o644, None)?;

    println!("config={CONFIG_PATH}");
    println!("identity={IDENTITY_PATH}");
    if !candidates.is_empty() {
        println!("mesh_key={MESH_KEY_PATH}");
        for candidate in &candidates {
            println!("mesh_member_candidate={candidate}");
        }
        println!(
            "nodes installed later list a candidate in [mesh] members, with a wildcard IP replaced by this node's public IP; confirm it against the `[relay] mesh listening=` startup log, which shows what actually bound"
        );
    }
    run_status(SYSTEMCTL, ["daemon-reload"])?;
    run_status(SYSTEMCTL, ["enable", SERVICE_NAME])?;
    run_status(SYSTEMCTL, ["restart", SERVICE_NAME])?;
    println!("installed and started {SERVICE_NAME}.service");
    println!("open inbound TCP and UDP port 19876 for IPv4 and IPv6");
    if !candidates.is_empty() {
        println!("open the backbone port (UDP 19877 by default) to the other members only");
    }
    println!("change options: sudoedit {CONFIG_PATH} && sudo minip2p-relay service restart");
    println!("logs: minip2p-relay service logs");
    Ok(())
}

/// Returns the service's backbone peer ID, creating its key at
/// [`MESH_KEY_PATH`] (service-owned, 0600) when missing and never replacing
/// an existing one.
fn ensure_backbone_key(service_uid: u32) -> Result<PeerId, Box<dyn Error>> {
    if let Some(peer_id) = existing_backbone(Path::new(MESH_KEY_PATH), service_uid)? {
        return Ok(peer_id);
    }
    let keypair = Ed25519Keypair::generate();
    install_key(
        encode_key_file(&keypair).as_bytes(),
        Path::new(MESH_KEY_PATH),
    )?;
    Ok(keypair.peer_id())
}

/// The peer ID of the backbone key at `path`, if one exists: a regular
/// 0600 file that `owner_uid` owns, as the relay will require at start.
#[cfg(not(unix))]
fn existing_backbone(_: &Path, _: u32) -> Result<Option<PeerId>, Box<dyn Error>> {
    Err("service management currently supports Linux systemd hosts only".into())
}

#[cfg(unix)]
fn existing_backbone(path: &Path, owner_uid: u32) -> Result<Option<PeerId>, Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(read_keypair_owned_by(path, owner_uid)?.peer_id())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display()).into()),
    }
}

fn uninstall() -> Result<(), Box<dyn Error>> {
    require_linux()?;
    require_root()?;
    let unit_exists = Path::new(UNIT_PATH).exists();
    let stop_status = ProcessCommand::new(SYSTEMCTL)
        .args(["stop", SERVICE_NAME])
        .status()
        .map_err(|error| format!("cannot run {SYSTEMCTL}: {error}"))?;
    if !stop_status.success() && service_is_loaded()? {
        return Err(format!("{SYSTEMCTL} stop {SERVICE_NAME} failed: {stop_status}").into());
    }

    if unit_exists {
        run_status(SYSTEMCTL, ["disable", SERVICE_NAME])?;
    }
    remove_enable_link(Path::new(ENABLED_UNIT_PATH))?;

    if unit_exists {
        fs::remove_file(UNIT_PATH)?;
    }
    run_status(SYSTEMCTL, ["daemon-reload"])?;
    if unit_exists {
        println!("removed {SERVICE_NAME}.service");
    } else {
        println!("{SERVICE_NAME}.service is not installed");
    }
    if Path::new(CONFIG_PATH).exists() {
        println!("config preserved at {CONFIG_PATH}");
    }
    println!("identity preserved at {IDENTITY_PATH}");
    if Path::new(MESH_KEY_PATH).exists() {
        println!("mesh key preserved at {MESH_KEY_PATH}");
    }
    Ok(())
}

fn service_is_loaded() -> Result<bool, Box<dyn Error>> {
    let output = ProcessCommand::new(SYSTEMCTL)
        .args(["show", "--property=LoadState", "--value", SERVICE_NAME])
        .output()
        .map_err(|error| format!("cannot run {SYSTEMCTL}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{SYSTEMCTL} show LoadState for {SERVICE_NAME} failed: {}",
            output.status
        )
        .into());
    }
    let state = std::str::from_utf8(&output.stdout)?.trim();
    Ok(state != "not-found")
}

fn remove_enable_link(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Err(format!(
            "refusing to remove non-symlink systemd enable path {}",
            path.display()
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn install_executable() -> Result<(), Box<dyn Error>> {
    let current = std::env::current_exe()?;
    let destination = Path::new(EXECUTABLE_PATH);
    if let (Ok(current), Ok(destination)) = (current.canonicalize(), destination.canonicalize())
        && current == destination
    {
        return Ok(());
    }
    run_status(
        INSTALL,
        [
            OsStr::new("-m"),
            OsStr::new("0755"),
            current.as_os_str(),
            destination.as_os_str(),
        ],
    )
}

fn read_import_identity(source: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = fs::File::open(source)
        .map_err(|error| format!("cannot open identity {}: {error}", source.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect identity {}: {error}", source.display()))?;
    if !metadata.is_file() {
        return Err(format!("identity {} is not a regular file", source.display()).into());
    }
    if metadata.len() > 65 {
        return Err(format!("identity {} is larger than 65 bytes", source.display()).into());
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    file.take(66).read_to_end(&mut encoded)?;
    let secret = encoded.strip_suffix(b"\n").unwrap_or(&encoded);
    if secret.len() != 64 || !secret.iter().all(u8::is_ascii_hexdigit) {
        return Err(format!(
            "identity {} must contain exactly 64 hexadecimal characters and an optional newline",
            source.display()
        )
        .into());
    }
    Ok(encoded)
}

/// Installs a service-owned 0600 key file at `destination`, never
/// replacing an existing one.
fn install_key(encoded: &[u8], destination: &Path) -> Result<(), Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = Path::new(IDENTITY_STAGING_DIR).join(format!(
        ".minip2p-relay.key.tmp-{}-{nonce}",
        std::process::id()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut staged = options.open(&temporary)?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        staged.write_all(encoded)?;
        staged.sync_all()?;
        run_status(CHOWN, [OsStr::new(SERVICE_USER), temporary.as_os_str()])?;
        publish_identity(&temporary, destination)
    })();
    if result.is_err() && fs::remove_file(&temporary).is_err() {
        // The primary write/install error remains more useful to callers.
    }
    result
}

fn publish_identity(staged: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    fs::hard_link(staged, destination)?;
    fs::remove_file(staged)?;
    Ok(())
}

/// Replaces `path` atomically with a `mode` file, owned by `owner`
/// (`user:group`) when given.
fn write_atomically(
    path: &Path,
    contents: &str,
    mode: u32,
    owner: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(mode);
        }
        let mut file = options.open(&temporary)?;
        // The umask may have narrowed the mode `open` applied.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        if let Some(owner) = owner {
            run_status(CHOWN, [OsStr::new(owner), temporary.as_os_str()])?;
        }
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() && fs::remove_file(&temporary).is_err() {
        // The primary write error remains more useful to callers.
    }
    result
}

fn user_exists(user: &str) -> Result<bool, Box<dyn Error>> {
    let output = ProcessCommand::new(ID)
        .args(["-u", user])
        .output()
        .map_err(|error| format!("cannot run {ID}: {error}"))?;
    Ok(output.status.success())
}

/// The service user's uid, which owns its key files.
fn service_uid() -> Result<u32, Box<dyn Error>> {
    let output = ProcessCommand::new(ID)
        .args(["-u", SERVICE_USER])
        .output()
        .map_err(|error| format!("cannot run {ID}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{ID} -u {SERVICE_USER} failed: {}", output.status).into());
    }
    Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
}

fn group_exists(group: &str) -> Result<bool, Box<dyn Error>> {
    let output = ProcessCommand::new(GETENT)
        .args(["group", group])
        .output()
        .map_err(|error| format!("cannot run {GETENT}: {error}"))?;
    Ok(output.status.success())
}

fn require_linux() -> Result<(), Box<dyn Error>> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err("service management currently supports Linux systemd hosts only".into())
    }
}

fn require_root() -> Result<(), Box<dyn Error>> {
    let output = ProcessCommand::new(ID)
        .arg("-u")
        .output()
        .map_err(|error| format!("cannot run {ID}: {error}"))?;
    if output.status.success() && matches!(output.stdout.as_slice(), b"0" | b"0\n") {
        Ok(())
    } else {
        Err("run this command with sudo".into())
    }
}

fn run_status<I, S>(program: &str, args: I) -> Result<(), Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = ProcessCommand::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}").into())
    }
}

fn command() -> ClapCommand {
    ClapCommand::new("minip2p-relay service")
        .about("Manage the Linux systemd service")
        .subcommand_required(true)
        .subcommand(
            ClapCommand::new("install")
                .about("Install and start a systemd service")
                .arg(
                    Arg::new("hostname")
                        .long("hostname")
                        .value_name("HOSTNAME")
                        .help("Install a minimal config announcing /dns/HOSTNAME, or keep the installed one if it names HOSTNAME"),
                )
                .arg(
                    Arg::new("config")
                        .long("config")
                        .value_name("FILE")
                        .value_parser(value_parser!(PathBuf))
                        .help("Install this relay.toml, replacing the installed one"),
                )
                .group(
                    ArgGroup::new("source")
                        .args(["hostname", "config"])
                        .required(true),
                )
                .arg(
                    Arg::new("import-key")
                        .long("import-key")
                        .value_name("PATH")
                        .help("Install this identity key; refuses to replace an existing one"),
                ),
        )
        .subcommand(ClapCommand::new("status").about("Show the systemd service status"))
        .subcommand(ClapCommand::new("logs").about("Follow the systemd service logs"))
        .subcommand(ClapCommand::new("restart").about("Restart the systemd service"))
        .subcommand(
            ClapCommand::new("uninstall")
                .about("Remove the systemd service and preserve its identity"),
        )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    const MEMBER: &str = "/ip4/203.0.113.10/udp/19877/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";

    #[test]
    fn unit_runs_the_relay_from_the_installed_config() {
        let unit = unit_file(Path::new("/opt/minip2p relay/%h")).unwrap();

        assert_eq!(
            unit,
            "[Unit]\n\
Description=minip2p circuit relay\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
User=minip2p-relay\n\
Group=minip2p-relay\n\
ExecStart=\"/opt/minip2p relay/%%h\" --config /etc/minip2p-relay/relay.toml\n\
Restart=on-failure\n\
RestartSec=5\n\
StandardInput=null\n\
UMask=0077\n\
NoNewPrivileges=true\n\
PrivateTmp=true\n\
ProtectHome=true\n\
ProtectSystem=strict\n\
ReadWritePaths=/var/lib/minip2p-relay\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n"
        );
    }

    #[test]
    fn a_hostname_install_writes_a_persistent_identity() {
        let prepared = prepare_config(Source::Hostname("relay.example.com"), None).unwrap();
        assert_eq!(
            prepared.text,
            "key = \"/var/lib/minip2p-relay/identity.key\"\nhostname = \"relay.example.com\"\n"
        );
        // The same key file on every start keeps the peer ID.
        assert_eq!(
            prepared.options.key_path.as_deref(),
            Some(Path::new(IDENTITY_PATH))
        );
        assert_eq!(prepared.options.announce_addrs.len(), 2);
    }

    #[test]
    fn a_hostname_install_keeps_the_existing_config() {
        let existing = "# tuned by hand\nkey = \"/var/lib/minip2p-relay/identity.key\"\nhostname = \"relay.example.com\"\n\n[limits]\nmax_circuits = 7\n";
        let prepared =
            prepare_config(Source::Hostname("relay.example.com"), Some(existing)).unwrap();
        assert_eq!(prepared.text, existing);
        assert_eq!(prepared.options.config.max_circuits, 7);

        let error =
            prepare_config(Source::Hostname("other.example.com"), Some(existing)).unwrap_err();
        assert!(
            error.contains("names hostname \"relay.example.com\""),
            "{error}"
        );
    }

    #[test]
    fn a_config_install_replaces_the_existing_one() {
        let prepared = prepare_config(Source::File("[limits]\nmax_circuits = 3\n"), None).unwrap();
        assert_eq!(
            prepared.text,
            "key = \"/var/lib/minip2p-relay/identity.key\"\n[limits]\nmax_circuits = 3\n"
        );
    }

    #[test]
    fn a_config_install_requires_the_service_key_paths() {
        let error = prepare_config(Source::File("key = \"/root/identity.key\""), None).unwrap_err();
        assert!(error.contains("use --import-key"), "{error}");
        let error = prepare_config(
            Source::File("key = \"/var/lib/minip2p-relay/identity.key/\""),
            None,
        )
        .unwrap_err();
        assert!(error.contains("use --import-key"), "{error}");
        let error = prepare_config(
            Source::File("[mesh]\nkey = \"/var/lib/minip2p-relay/identity.key\""),
            None,
        )
        .unwrap_err();
        assert!(error.contains("[mesh] key must be"), "{error}");
        let error = prepare_config(
            Source::File("[webtransport]\ncert = \"fullchain.pem\"\nkey = \"/k.pem\""),
            None,
        )
        .unwrap_err();
        assert!(error.contains("absolute paths"), "{error}");
    }

    #[test]
    fn a_bare_mesh_section_gets_the_service_backbone_key() {
        let source =
            format!("hostname = \"relay.example.com\"\n\n[mesh] # on\nmembers = [\"{MEMBER}\"]\n");
        let prepared = prepare_config(Source::File(&source), None).unwrap();
        assert_eq!(
            prepared.text,
            format!(
                "key = \"/var/lib/minip2p-relay/identity.key\"\nhostname = \"relay.example.com\"\n\n[mesh] # on\nkey = \"/var/lib/minip2p-relay/mesh.key\"\nmembers = [\"{MEMBER}\"]\n"
            )
        );
        let mesh = prepared.options.mesh.unwrap();
        assert_eq!(mesh.key_path, Path::new(MESH_KEY_PATH));
        assert_eq!(mesh.members, [MEMBER.parse().unwrap()]);
        // A header on the last line, without its newline.
        let prepared = prepare_config(Source::File("[mesh]"), None).unwrap();
        assert!(
            prepared
                .text
                .ends_with("[mesh]\nkey = \"/var/lib/minip2p-relay/mesh.key\"\n")
        );
    }

    #[test]
    fn a_mesh_listen_port_of_zero_is_rejected() {
        let error =
            prepare_config(Source::File("[mesh]\nlisten = [\"0.0.0.0:0\"]"), None).unwrap_err();
        assert!(error.contains("set a fixed port"), "{error}");
    }

    #[test]
    fn mesh_member_candidates_cover_each_bind() {
        let peer = Ed25519Keypair::generate().peer_id();
        assert_eq!(
            mesh_member_candidates(&[], &peer),
            [
                format!("/ip4/0.0.0.0/udp/19877/quic-v1/p2p/{peer}"),
                format!("/ip6/::/udp/19877/quic-v1/p2p/{peer}"),
            ]
        );
        let bind: SocketAddr = "[2001:db8::7]:4301".parse().unwrap();
        assert_eq!(
            mesh_member_candidates(&[bind], &peer),
            [format!("/ip6/2001:db8::7/udp/4301/quic-v1/p2p/{peer}")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_repeat_mesh_install_reads_the_existing_backbone_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mesh.key");
        let uid = rustix::process::geteuid().as_raw();
        assert_eq!(existing_backbone(&path, uid).unwrap(), None);

        let keypair = Ed25519Keypair::generate();
        std::fs::write(&path, encode_key_file(&keypair)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = existing_backbone(&path, uid).unwrap_err().to_string();
        assert!(error.contains("mode must be 0600"), "{error}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            existing_backbone(&path, uid).unwrap(),
            Some(keypair.peer_id())
        );
        let error = existing_backbone(&path, uid + 1).unwrap_err().to_string();
        assert!(error.contains("owned by uid"), "{error}");
    }

    #[test]
    fn identity_import_rejects_a_malformed_secret() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("identity.key");
        std::fs::write(&source, b"not-an-ed25519-secret\n").unwrap();

        let error = read_import_identity(&source).unwrap_err();

        assert!(error.to_string().contains("64 hexadecimal characters"));
    }

    #[test]
    fn identity_import_never_removes_an_existing_identity() {
        let directory = tempfile::tempdir().unwrap();
        let staged = directory.path().join("staged.key");
        let destination = directory.path().join("identity.key");
        std::fs::write(&staged, b"replacement identity").unwrap();
        std::fs::write(&destination, b"existing identity").unwrap();

        let error = publish_identity(&staged, &destination).unwrap_err();

        assert_eq!(std::fs::read(destination).unwrap(), b"existing identity");
        assert_eq!(std::fs::read(staged).unwrap(), b"replacement identity");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }

    #[cfg(unix)]
    #[test]
    fn written_files_take_the_requested_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        for mode in [0o644, 0o640] {
            let path = directory.path().join(format!("file-{mode:o}"));
            write_atomically(&path, "contents", mode, None).unwrap();
            let actual = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(actual, mode);
        }
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_removes_a_dangling_enable_link() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("minip2p-relay.service");
        symlink("../missing/minip2p-relay.service", &link).unwrap();

        remove_enable_link(&link).unwrap();

        std::fs::symlink_metadata(link).expect_err("failed install must remove the temporary link");
    }
}
