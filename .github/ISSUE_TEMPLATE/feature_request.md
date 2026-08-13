name: Feature Request
description: Suggest an idea or feature for secure-agent
title: "[FEATURE] "
labels: ["enhancement"]
assignees: []
body:
  - type: markdown
    attributes:
      value: Have a feature idea for secure-agent? Tell us about it!
  - type: textarea
    id: problem
    attributes:
      label: Problem or Rationale
      description: Is your feature request related to a problem or new use-case?
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution
      description: Clear description of what you want to happen.
    validations:
      required: true
