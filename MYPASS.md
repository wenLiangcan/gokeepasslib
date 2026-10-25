# MyPass maintained fork

Fork: https://github.com/wenLiangcan/gokeepasslib
Upstream: https://github.com/tobischo/gokeepasslib
Patch branch: master, based on upstream v3.7.1.
The upstream module path and MIT license are retained for compatibility.

Changes from v3.7.1:

- header.go: expose the KDBX 4 Argon2id UUID as KdfArgon2id.
- credentials.go: dispatch that UUID to golang.org/x/crypto/argon2.IDKey;
  retain github.com/tobischo/argon2.DKey for Argon2d. Reject unknown KDFs
  rather than treating them as AES-KDF.
- argon2id_test.go: cover KDF dispatch, memory-unit conversion, parameter
  serialization, wrong passwords, and rejection of unknown KDFs.
- vendor/: include the official Go Argon2 implementation used by IDKey.

Run `CGO_ENABLED=0 go test ./... -count=1` and `CGO_ENABLED=0 go vet ./...`
before publishing updates. MyPass additionally verifies resource limits, safe
writes, quick unlock, and KeePassXC read/edit/write interoperability in its
internal/vault tests. Resource limits are enforced by MyPass before decoding;
this fork does not impose application-specific memory or iteration ceilings.

When updating from upstream, merge the selected upstream release into this
branch, review changes to KDF dispatch and serialization, run both test suites,
and publish the branch before updating MyPass's submodule pointer. Keep the
patch small and retire it when upstream provides equivalent functionality.
