use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn operator_cli_prints_the_release_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_minip2p-relay"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("minip2p-relay {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn operator_help_points_to_service_installation() {
    let output = Command::new(env!("CARGO_BIN_EXE_minip2p-relay"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("usage: minip2p-relay "), "{stdout}");
    assert!(stdout.contains("IPv6 port 19876"), "{stdout}");
    assert!(
        stdout.contains("minip2p-relay service install --hostname HOSTNAME"),
        "{stdout}"
    );
}

#[test]
fn service_install_help_describes_the_host_setup() {
    let output = Command::new(env!("CARGO_BIN_EXE_minip2p-relay"))
        .args(["service", "install", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--hostname <HOSTNAME>"), "{stdout}");
    assert!(stdout.contains("--import-key <PATH>"), "{stdout}");
    assert!(stdout.contains("--webtransport-cert <PATH>"), "{stdout}");
    assert!(
        stdout.contains("Install and start a systemd service"),
        "{stdout}"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn service_install_rejects_an_invalid_hostname_before_touching_the_host() {
    let output = Command::new(env!("CARGO_BIN_EXE_minip2p-relay"))
        .args(["service", "install", "--hostname", "not a hostname"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid --hostname"), "{stderr}");
    assert!(stderr.contains("not a hostname"), "{stderr}");
}

#[test]
fn webtransport_prints_the_certhash_address_on_the_quic_port() {
    let mut relay = Command::new(env!("CARGO_BIN_EXE_minip2p-relay"))
        .args([
            "--webtransport",
            "--quic",
            "127.0.0.1:0",
            "--tcp",
            "127.0.0.1:0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = relay.stdout.take().unwrap();
    let mut quic = None;
    let mut webtransport = None;
    for line in BufReader::new(stdout).lines() {
        let line = line.unwrap();
        if let Some(address) = line.strip_prefix("[relay] webtransport=") {
            webtransport = Some(address.to_owned());
            break;
        }
        if let Some(address) = line.strip_prefix("[relay] listening=")
            && address.contains("/quic-v1/p2p/")
        {
            quic = Some(address.to_owned());
        }
    }
    relay.kill().unwrap();
    relay.wait().unwrap();

    let webtransport = webtransport.expect("a WebTransport address");
    let quic = quic.expect("a quic-v1 address");
    assert!(
        webtransport.contains("/webtransport/certhash/u"),
        "{webtransport}"
    );
    let socket = |address: &str| address.split("/quic-v1").next().unwrap().to_owned();
    assert_eq!(socket(&webtransport), socket(&quic));
}

#[test]
fn a_ca_certificate_prints_the_announced_hash_free_address_and_its_expiry() {
    let fixture = |name: &str| {
        format!(
            "{}/../../transports/quic/tests/fixtures/ca/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    };
    let mut relay = Command::new(env!("CARGO_BIN_EXE_minip2p-relay"))
        .args(["--quic", "127.0.0.1:0", "--tcp", "127.0.0.1:0"])
        .args(["--webtransport-cert", &fixture("localhost.pem")])
        .args(["--webtransport-key", &fixture("localhost.key")])
        .args([
            "--announce",
            "/dns/localhost/udp/19876/quic-v1/webtransport",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = relay.stdout.take().unwrap();
    let mut webtransport = Vec::new();
    let mut not_after = None;
    for line in BufReader::new(stdout).lines() {
        let line = line.unwrap();
        if let Some(address) = line.strip_prefix("[relay] webtransport=") {
            webtransport.push(address.to_owned());
        }
        if let Some(time) = line.strip_prefix("[relay] webtransport_certificate_not_after=") {
            not_after = Some(time.to_owned());
            break;
        }
    }
    relay.kill().unwrap();
    relay.wait().unwrap();

    // Only the announced address: the listener's IP fails the certificate's name.
    assert_eq!(webtransport.len(), 1, "{webtransport:?}");
    assert!(
        webtransport[0].starts_with("/dns/localhost/udp/19876/quic-v1/webtransport/p2p/"),
        "{webtransport:?}"
    );
    assert_eq!(not_after.as_deref(), Some("2125-12-31T00:00:00Z"));
}

#[test]
fn a_renewed_ca_certificate_is_served_without_a_restart() {
    let fixture = |name: &str| {
        format!(
            "{}/../../transports/quic/tests/fixtures/ca/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    };
    let dir = tempfile::tempdir().unwrap();
    let (chain, key) = (
        dir.path().join("fullchain.pem"),
        dir.path().join("privkey.pem"),
    );
    // Explicit times: a filesystem's mtime granularity can hide a rewrite.
    let install = |from: &str, to: &std::path::Path, secs: u64| {
        std::fs::copy(fixture(from), to).unwrap();
        std::fs::File::options()
            .write(true)
            .open(to)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    };
    install("chain.pem", &chain, 1);
    install("chain.key", &key, 1);

    let mut relay = Command::new(env!("CARGO_BIN_EXE_minip2p-relay"))
        .args(["--quic", "127.0.0.1:0", "--tcp", "127.0.0.1:0"])
        .arg("--webtransport-cert")
        .arg(&chain)
        .arg("--webtransport-key")
        .arg(&key)
        .args(["--webtransport-reload-secs", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (lines, receiver) = mpsc::channel();
    let stdout = relay.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if lines.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let wait_for = |prefix: &str| loop {
        match receiver.recv_timeout(Duration::from_secs(20)) {
            Ok(line) if line.starts_with(prefix) => break Some(line),
            Ok(_) => {}
            Err(_) => break None,
        }
    };

    let started = wait_for("[relay] webtransport_certificate_not_after=");
    // The certbot deploy hook's order: chain first, then key.
    install("localhost.pem", &chain, 2);
    install("localhost.key", &key, 2);
    let reloaded = wait_for("[relay] webtransport certificate reloaded ");
    relay.kill().unwrap();
    relay.wait().unwrap();

    assert!(started.is_some(), "the relay never started");
    assert_eq!(
        reloaded.as_deref(),
        Some("[relay] webtransport certificate reloaded not_after=2125-12-31T00:00:00Z")
    );
}

/// Writes `keypair` as a relay key file: hex secret, owner-only.
#[cfg(unix)]
fn write_key(path: &std::path::Path, keypair: &minip2p::Ed25519Keypair) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let hex: String = keypair
        .secret_key_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(hex.as_bytes()))
        .expect("write a key file");
}

#[cfg(unix)]
#[test]
fn two_mesh_nodes_report_each_other_up() {
    let dir = tempfile::tempdir().unwrap();
    let public = dir.path().join("identity.key");
    write_key(&public, &minip2p::Ed25519Keypair::generate());
    let nodes: Vec<_> = (0..2)
        .map(|index| {
            let key = dir.path().join(format!("mesh-{index}.key"));
            let keypair = minip2p::Ed25519Keypair::generate();
            write_key(&key, &keypair);
            // A port no socket holds now, so each node can list the other.
            let port = std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let member = format!(
                "/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{}",
                keypair.peer_id()
            );
            (key, port, member)
        })
        .collect();

    let mut relays = Vec::new();
    let (lines, receiver) = mpsc::channel();
    for (index, (key, port, _)) in nodes.iter().enumerate() {
        let mut relay = Command::new(env!("CARGO_BIN_EXE_minip2p-relay"))
            .args(["--quic", "127.0.0.1:0", "--tcp", "127.0.0.1:0", "--key"])
            .arg(&public)
            .arg("--mesh-key")
            .arg(key)
            .args(["--mesh-listen", &format!("127.0.0.1:{port}")])
            .args(
                nodes
                    .iter()
                    .flat_map(|(_, _, member)| ["--mesh-member", member]),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = relay.stdout.take().unwrap();
        let lines = lines.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if lines.send((index, line.unwrap())).is_err() {
                    break;
                }
            }
        });
        relays.push(relay);
    }

    let mut listening = [false; 2];
    let mut up = [false; 2];
    while !(listening.iter().all(|&seen| seen) && up.iter().all(|&seen| seen)) {
        let Ok((index, line)) = receiver.recv_timeout(Duration::from_secs(20)) else {
            break;
        };
        let (own, other) = (&nodes[index].2, &nodes[1 - index].2);
        listening[index] |= line == format!("[relay] mesh listening={own}");
        let other_peer = other.rsplit('/').next().unwrap();
        up[index] |= line == format!("[relay] mesh member={other_peer} up");
    }
    for mut relay in relays {
        relay.kill().unwrap();
        relay.wait().unwrap();
    }

    assert_eq!(
        listening, [true; 2],
        "each node prints its backbone address"
    );
    assert_eq!(up, [true; 2], "each node reports the other member up");
}
