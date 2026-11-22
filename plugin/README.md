# Secure Agent hooks

The Secure Agent app installs and manages hooks for Claude Code, Cursor, Codex, OpenClaw, Antigravity, Hermes, and OpenCode v2. See [Getting started](https://github.com/cavi-ai/secure-agent/blob/main/docs/GETTING_STARTED.md) for setup and coverage. Python hooks require Python 3.12 or later on your PATH.

## Claude Code marketplace

Claude Code users can also install the Secure Agent hooks through the CAVI marketplace:

```sh
claude plugin marketplace add cavi-ai/plugins
claude plugin install secure-agent@cavi-ai --scope user
```

Use one Secure Agent hook integration for Claude Code. This plugin supplies the hooks; separate manual hook registration is unnecessary. Check session coverage in Secure Agent after setup.

## Local plugin packages

Generate a package in a new directory (its parent must already exist):

```sh
python3 plugin/package_marketplace.py --host claude --output /tmp/secure-agent-claude
```

Choose one of the following values for `--host`. Replace `<package>` with the generated directory.

| Host | Installation |
| --- | --- |
| Claude Code (`claude`) | Run `claude --plugin-dir <package>`, or use the CAVI marketplace above. |
| Codex (`codex`) | Add a local marketplace entry using the [local plugin guide](https://developers.openai.com/plugins/build/plugins#test-your-plugin-locally). Review and trust the hooks with `/hooks`. |
| Cursor (`cursor`) | Run `cursor-agent --plugin-dir <package>`. |
| Antigravity (`antigravity`) | Run `agy plugin install <package>`. |
| OpenClaw (`openclaw`) | Run `openclaw plugins install <package>` and follow the interactive trust flow. |
| Hermes (`hermes`) | Place the package in `~/.hermes/plugins/secure-agent` and run `hermes plugins enable secure-agent`. See the [Hermes plugin guide](https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins). |
| OpenCode v2 (`opencode`) | Add the package directory to `plugins` in `opencode.json(c)`. See the [OpenCode plugin guide](https://opencode.ai/docs/plugins/). |

Use one Secure Agent hook integration per host. Disable the previous hook integration before enabling a package, and keep Secure Agent's manual setup hooks disabled while the package is enabled. Restart the host after changing its plugin setup.
