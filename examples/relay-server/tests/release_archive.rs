#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn release_archive_is_self_describing_and_runnable() {
    let version = env!("CARGO_PKG_VERSION");
    let target = "test-host";
    let output_dir = tempfile::tempdir().unwrap();

    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new(repository.join("scripts/package-relay-server.sh"))
        .args([version, target, env!("CARGO_BIN_EXE_minip2p-relay-server")])
        .arg(output_dir.path())
        .status()
        .unwrap();
    assert!(status.success());

    let archive_name = format!("minip2p-relay-server-v{version}-{target}");
    let archive = output_dir.path().join(format!("{archive_name}.tar.gz"));
    let extract = output_dir.path().join("extract");
    std::fs::create_dir(&extract).unwrap();
    let status = Command::new("tar")
        .args(["-xzf"])
        .arg(&archive)
        .args(["-C"])
        .arg(&extract)
        .status()
        .unwrap();
    assert!(status.success());

    let contents = extract.join(archive_name);
    assert!(contents.join("README.md").is_file());
    assert!(contents.join("LICENSE").is_file());
    let binary = contents.join("minip2p-relay-server");
    assert_eq!(
        std::fs::metadata(&binary).unwrap().permissions().mode() & 0o777,
        0o755
    );
    let output = Command::new(binary).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("minip2p-relay-server {version}\n")
    );
}
