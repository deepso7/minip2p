# CA test fixtures

Static PEM files for the CA-certificate WebTransport tests (`tests/webtransport.rs`). Test-only: the private keys are public.

| File | What it is |
| --- | --- |
| `ca.pem` | Root CA (`CA:TRUE`), valid 2026 to 2125 |
| `other-ca.pem` | An unrelated root CA, for the untrusted-root test |
| `localhost.pem`, `localhost.key` | ECDSA P-256 leaf signed by `ca.pem`: SAN `DNS:localhost`, `CA:FALSE`, valid 2026 to 2125 |
| `expired.pem`, `expired.key` | The same profile, valid only in 2020 |

The CA keys are not kept. Regenerate everything with OpenSSL 3 (macOS's LibreSSL lacks `-not_before`/`-not_after`), from this directory:

```bash
O=/opt/homebrew/opt/openssl@3/bin/openssl
for ca in ca other-ca; do
  $O req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout /tmp/$ca.key -out $ca.pem -subj "/CN=minip2p test $ca" \
    -not_before 20260101000000Z -not_after 21251231000000Z \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
done
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n' > /tmp/leaf.ext
for leaf in localhost:20260101000000Z:21251231000000Z expired:20200101000000Z:20210101000000Z; do
  IFS=: read name nb na <<< "$leaf"
  $O req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout $name.key -out /tmp/$name.csr -subj "/CN=localhost"
  $O x509 -req -in /tmp/$name.csr -CA ca.pem -CAkey /tmp/ca.key \
    -not_before $nb -not_after $na -extfile /tmp/leaf.ext -out $name.pem
done
```
