use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, Command as ClapCommand};

const SERVICE_NAME: &str = "minip2p-relay";
const SERVICE_USER: &str = "minip2p-relay";
const STATE_DIR: &str = "/var/lib/minip2p-relay";
const IDENTITY_PATH: &str = "/var/lib/minip2p-relay/identity.key";
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
            let hostname = matches
                .get_one::<String>("hostname")
                .expect("clap requires --hostname");
            validate_hostname(hostname)?;
            let import_key = matches.get_one::<String>("import-key").map(Path::new);
            install(hostname, import_key)
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

fn validate_hostname(hostname: &str) -> Result<(), Box<dyn Error>> {
    let valid = !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if valid {
        Ok(())
    } else {
        Err(format!("invalid --hostname {hostname:?}: expected a DNS hostname").into())
    }
}

fn unit_file(executable: &Path, hostname: &str) -> Result<String, Box<dyn Error>> {
    let executable = executable
        .to_str()
        .ok_or("the relay executable path is not valid UTF-8")?;
    if executable.chars().any(char::is_control) {
        return Err("the relay executable path contains a control character".into());
    }
    let executable = executable.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!(
        "[Unit]\n\
Description=minip2p circuit relay\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
User=minip2p-relay\n\
Group=minip2p-relay\n\
ExecStart=\"{executable}\" --key /var/lib/minip2p-relay/identity.key --announce /dns/{hostname}/tcp/19876 --announce /dns/{hostname}/udp/19876/quic-v1\n\
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

fn install(hostname: &str, import_key: Option<&Path>) -> Result<(), Box<dyn Error>> {
    require_linux()?;
    require_root()?;
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
        install_identity(&identity)?;
    }
    let unit = unit_file(Path::new(EXECUTABLE_PATH), hostname)?;
    write_unit_atomically(Path::new(UNIT_PATH), &unit)?;

    run_status(SYSTEMCTL, ["daemon-reload"])?;
    run_status(SYSTEMCTL, ["enable", SERVICE_NAME])?;
    run_status(SYSTEMCTL, ["restart", SERVICE_NAME])?;
    println!("installed and started {SERVICE_NAME}.service");
    println!("identity={IDENTITY_PATH}");
    println!("open inbound TCP and UDP port 19876 for IPv4 and IPv6");
    println!("logs: minip2p-relay service logs");
    Ok(())
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
    println!("identity preserved at {IDENTITY_PATH}");
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

fn install_identity(encoded: &[u8]) -> Result<(), Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = Path::new(IDENTITY_STAGING_DIR).join(format!(
        ".minip2p-relay.identity.tmp-{}-{nonce}",
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
        publish_identity(&temporary, Path::new(IDENTITY_PATH))
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

fn write_unit_atomically(path: &Path, contents: &str) -> Result<(), Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o644);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
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
                        .required(true),
                )
                .arg(Arg::new("import-key").long("import-key").value_name("PATH")),
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

    #[test]
    fn unit_runs_the_relay_with_persistent_identity_and_dns_announcements() {
        let unit = unit_file(
            Path::new("/opt/minip2p relay/minip2p-relay"),
            "relay.minip2p.com",
        )
        .unwrap();

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
ExecStart=\"/opt/minip2p relay/minip2p-relay\" --key /var/lib/minip2p-relay/identity.key --announce /dns/relay.minip2p.com/tcp/19876 --announce /dns/relay.minip2p.com/udp/19876/quic-v1\n\
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
    fn systemd_unit_is_not_writable_by_other_users() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("minip2p-relay.service");

        write_unit_atomically(&path, "unit contents").unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o022, 0);
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
