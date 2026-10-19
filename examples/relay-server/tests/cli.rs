use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

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
