# Bench bootstrap converges without losing the runner, the key or the token

`infra/bench/bootstrap.sh` is rerun against live infrastructure, so it orders and guards its steps so that no failure leaves the repository worse off than before:

- **The registration token never reaches output.** `render_user_data` prints the user data with a live runner registration token, so it only ever writes to a private (`umask 077`) temp file, which is gzipped (cloud-init accepts gzip) to stay under EC2's 16 KB user-data limit and removed on exit.
- **Everything that can fail runs before `--replace` terminates the old instance**: the AMI lookup, the token request and the user-data render and size check. A failure never leaves the repository without a runner.
- **Key pairs are created only on a definite `InvalidKeyPair.NotFound`.** Any other `describe-key-pairs` error stops the script, and an existing key file is never overwritten, because AWS cannot return a lost private key.
- **The CI role converges to exactly one inline policy and no attached ones.** The policy listings use JSON output, which distinguishes an empty list from a policy named `None`, and each listing is captured into a variable first so a failed call stops the script under `set -e` (a process substitution would swallow the failure).
- **The role trusts `aws-bench-unattended` only after its permissions have converged**, so the unattended environment never assumes a role with a stale, broader policy.
- **`--no-ssh` revokes all-protocol rules too** (`IpProtocol -1`, ports -1), since they also admit SSH.
