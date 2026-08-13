## Summary

<!-- Brief description of the changes introduced in this PR -->

## Type of Change

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 🔒 Security enhancement
- [ ] 📝 Documentation update
- [ ] 🎨 Refactoring / Code style cleanups

## Verification Checklist

- [ ] `go test ./...` passes cleanly
- [ ] `python3 plugin/hooks/test_secret_guard.py` and other python hook tests pass
- [ ] `swift test --package-path menubar` passes
- [ ] `./packaging/test/e2e_smoke.sh` passes
- [ ] No secrets, tokens, or private keys are exposed or committed
