---
title: SSH keys and the SSH agent
summary: Create, load and authorize an SSH key (ed25519 or a hardware key), wire it into ~/.ssh/config and GitHub, and test it.
keywords: ssh, ssh-keygen, ssh-add, ssh-agent, id_ed25519, ed25519, authorized_keys, known_hosts, ssh config, deploy key, yubikey, fido, ed25519-sk
---
Rules
- A private key never leaves ~/.ssh and is never printed, copied or pasted. Only the .pub file is shareable.
- The passphrase is typed by the operator at the ssh-keygen / ssh-add prompt, so key creation and loading are terminal work.
- secure-agent's guard asks before an agent reads ~/.ssh; that prompt is expected, approve only the file the step names.

Look first
- ls -l ~/.ssh
- ssh-add -l                                   # keys the agent holds
- ssh -G github.com | grep -i identityfile     # the key ssh would offer

Create a key (terminal)
- ssh-keygen -t ed25519 -C "<label, e.g. user@host>" -f ~/.ssh/id_ed25519_<name>
- Hardware key (touch required): ssh-keygen -t ed25519-sk -C "<label>" -f ~/.ssh/id_ed25519_sk_<name>
- chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_ed25519_<name> && chmod 644 ~/.ssh/id_ed25519_<name>.pub

Load it
- macOS (passphrase kept in the login Keychain): ssh-add --apple-use-keychain ~/.ssh/id_ed25519_<name>
- Linux: eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_ed25519_<name>

~/.ssh/config (mode 600)
    Host github.com
      AddKeysToAgent yes
      UseKeychain yes            # macOS only; delete this line on Linux
      IdentityFile ~/.ssh/id_ed25519_<name>
      IdentitiesOnly yes

Authorize it
- GitHub: gh ssh-key add ~/.ssh/id_ed25519_<name>.pub --title "<host>"
  (needs the admin:public_key scope: gh auth refresh -h github.com -s admin:public_key)
- A server: ssh-copy-id -i ~/.ssh/id_ed25519_<name>.pub user@host
- Deploy key for one repository: add the .pub under the repository's Settings → Deploy keys, read-only unless it must push.

Test
- ssh -T git@github.com        # "Hi <user>! You've successfully authenticated"
- First connection: compare the host fingerprint with the provider's published one before answering yes; never pipe ssh-keyscan into known_hosts unchecked.

Retire a key
- Remove it from every place it was authorized (gh ssh-key list / gh ssh-key delete <id>), then delete both files.
