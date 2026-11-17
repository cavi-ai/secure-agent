# Secure Agent for Claude Code

Connect Claude Code activity and configured guard hooks to Secure Agent. Install and configure Secure Agent first; see [Getting started](https://github.com/cavi-ai/secure-agent/blob/main/docs/GETTING_STARTED.md) for setup and coverage. The plugin requires Python 3 on your PATH.

Add the CAVI marketplace and install the plugin:

```sh
claude plugin marketplace add cavi-ai/plugins
claude plugin install secure-agent@cavi-ai
```

Use one Secure Agent hook integration for Claude Code. This plugin supplies the hooks; separate manual hook registration is unnecessary. Check session coverage in Secure Agent after setup.
