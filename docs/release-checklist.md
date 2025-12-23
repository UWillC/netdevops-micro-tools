# Release Checklist

This checklist helps keep releases consistent and low-risk.

---

## Pre-release checks

- [ ] All planned features for this version are merged to `main`
- [ ] `CHANGELOG.md` updated (no unreleased changes mixed in)
- [ ] README reflects the current state of the project
- [ ] Docker image builds successfully
- [ ] API starts without errors
- [ ] Swagger UI works (`/docs`)
- [ ] Web UI sanity check:
  - SNMPv3 generator
  - NTP generator
  - AAA / TACACS+
  - Golden Config
  - CVE Analyzer
  - Profiles (list / load / save / delete)
- [ ] Profiles persistence documented (Docker volume mapping)

---

## Versioning

- [ ] Decide version number (patch / minor / major)
- [ ] Verify no breaking changes without version bump

---

## Tag & push

```bash
git pull
git status
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

---

## GitHub Release

- [ ] Create GitHub Release from the tag
- [ ] Paste notes from `docs/releases/vX.Y.Z.md`
- [ ] Verify release page renders correctly

---

## Post-release

- [ ] Confirm repository shows correct latest release
- [ ] Confirm no hotfix commits were missed
- [ ] Optionally announce release (LinkedIn / blog / notes)

---
