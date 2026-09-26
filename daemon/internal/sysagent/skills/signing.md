---
title: Commit and tag signing
summary: Sign commits and tags with an SSH key or GPG, register the signing key with GitHub, and verify signatures.
keywords: signing, sign, signed commits, gpgsign, gpg, gnupg, pinentry, signingkey, verify-commit, allowed_signers, ssh signing, tag signing, verified
---
Rules
- Private signing keys are never exported or printed (no gpg --export-secret-keys, no cat of a private key).
- Passphrases go through pinentry or the SSH agent prompt: terminal work for the operator.

SSH signing (simplest; reuses an SSH key, see the ssh skill)
- git config --global gpg.format ssh
- git config --global user.signingkey ~/.ssh/id_ed25519_<name>.pub
- git config --global commit.gpgsign true
- git config --global tag.gpgsign true
- Local verification: mkdir -p ~/.config/git && echo "<email> namespaces=\"git\" $(cat ~/.ssh/id_ed25519_<name>.pub)" >> ~/.config/git/allowed_signers
  then git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
- GitHub: gh ssh-key add ~/.ssh/id_ed25519_<name>.pub --type signing --title "<host> signing"
  (needs the scope: gh auth refresh -h github.com -s admin:ssh_signing_key)

GPG signing
- gpg --full-generate-key          # terminal: choose ed25519 / cv25519, set the passphrase
- gpg --list-secret-keys --keyid-format=long     # the key id follows "sec   ed25519/"
- git config --global user.signingkey <KEYID>
- git config --global gpg.program "$(command -v gpg)"
- git config --global commit.gpgsign true
- macOS passphrase prompt: brew install pinentry-mac ; echo "pinentry-program $(command -v pinentry-mac)" >> ~/.gnupg/gpg-agent.conf ; gpgconf --kill gpg-agent
- GitHub: gpg --armor --export <KEYID> | gh gpg-key add -     (public key only; scope admin:gpg_key)

Verify
- git commit --allow-empty -m "signing check" && git log --show-signature -1
- git verify-commit HEAD ; git verify-tag <tag>
- The commit email must match an email on the GitHub account for the "Verified" badge.
