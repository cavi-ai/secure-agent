---
title: Git identity and credentials
summary: Set the commit identity, store Git credentials in the OS keychain or the GitHub CLI, switch remotes to SSH, and find tokens left in plain text.
keywords: git, git config, credential, credential helper, osxkeychain, libsecret, gh auth, github cli, personal access token, pat, https remote, remote url, user.email, user.name, includeif
---
Rules
- Tokens live in a credential store (macOS Keychain, libsecret, gh), never in a remote URL, a repository file or ~/.git-credentials.
- gh auth login opens a browser or asks for a device code: terminal work for the operator.

Look first
- git config --show-origin --get-all credential.helper
- git config --global --get user.name ; git config --global --get user.email
- gh auth status
- Plain-text tokens: git config --get-regexp 'remote\..*\.url' | grep '@' ; ls -l ~/.git-credentials

Identity
- git config --global user.name "<name>"
- git config --global user.email "<email>"
- A second identity for one folder of repositories, in ~/.gitconfig:
      [includeIf "gitdir:~/work/"]
        path = ~/.gitconfig-work
  with ~/.gitconfig-work holding its own [user] block.

Credentials over HTTPS
- GitHub CLI (recommended): gh auth login --hostname github.com --git-protocol https --web ; then gh auth setup-git
- macOS Keychain: git config --global credential.helper osxkeychain
- Linux: git config --global credential.helper libsecret (git-credential-libsecret package), or cache --timeout=3600 for memory only.
- Never: git config credential.helper store (writes the token to ~/.git-credentials in plain text).

Switch a remote to SSH (see the ssh skill for the key)
- git remote set-url origin git@github.com:<owner>/<repo>.git
- git ls-remote origin >/dev/null && echo ok

Clean up a token in a URL
- git remote set-url origin https://github.com/<owner>/<repo>.git
- Revoke the exposed token at https://github.com/settings/tokens and create a new fine-grained one scoped to the repositories that need it.
