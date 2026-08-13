name: Bug Report
description: Create a report to help us fix a bug or issue in secure-agent
title: "[BUG] "
labels: ["bug"]
assignees: []
body:
  - type: markdown
    attributes:
      value: Thank you for taking the time to report a bug!
  - type: textarea
    id: description
    attributes:
      label: Bug Description
      description: Clear and concise description of what the bug is.
    validations:
      required: true
  - type: textarea
    id: steps
    attributes:
      label: Steps to Reproduce
      description: Steps to reproduce the behavior.
    validations:
      required: true
  - type: textarea
    id: environment
    attributes:
      label: Environment Information
      description: Operating system version, Go version, Agent harness (Claude Code, Cursor, etc.).
    validations:
      required: true
