- `amazon-linux-2-99E617FE5DB527C0D8BD5F8E11CF1F95C87F5B1A.asc`: Amazon Linux 2's RPM signing key, fetched
  from keyserver.ubuntu.com (not independently anchored). It signs every source RPM in `releases.json`.
- `openssl-EFC0A467D613CB83C7ED6D30D894E2CE8B3D79F5.asc`: the OpenSSL key that signed 1.1.1w (revoked by
  OpenSSL on 19 Jun 2024 in a key rotation; the 2023 signature still verifies).
- `allowed_signers`: added with the first signed release; the maintainer's SSH signing key, for
  `git tag -v` (`git config gpg.ssh.allowedSignersFile keys/allowed_signers`) and
  `ssh-keygen -Y verify -n file` of `SHA256SUMS.sig`.
