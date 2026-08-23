use std::process::Command;

#[test]
fn prints_the_release_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_minip2p-relay-server"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("minip2p-relay-server {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}
