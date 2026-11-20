# Release procedure

How a change reaches production, written down from what the repo history, the
workflows and the scripts show (v0.7.10 to v0.7.18, October and November 2026).
Anything not proven by history, a workflow or a script is marked [VERIFY].

Production: app `https://netdevops-tools.thebackroom.ai`, Render web service
`netdevops-micro-tools` (Docker, `render.yaml`). Auto-deploy is OFF in Render; the
only automatic deploy path is the `deploy` job in `.github/workflows/tests.yml`.

## 0. Before the release

- The work lives on its own branch (`feat/...`, `fix/...`, `auto/YYYY-MM-DD-...`),
  usually in a worktree `~/SaaS/cisco-microtool-generator-wt-<name>`.
- Full suite green locally, with the same settings as CI:

  ```sh
  PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python CVE_WARMUP_SYNC=0 \
    .venv/bin/python -m pytest -q -p no:cacheprovider tests/
  ```

  (A worktree has no `.venv`: use the interpreter of the main checkout,
  `/Users/uwillc/SaaS/cisco-microtool-generator/.venv/bin/python`.)
- Security-relevant changes are reviewed by @ciso first; the verdict (GO / GO with
  conditions / NO-GO) is named in the release commit message ("reviewed by @ciso, GO").

## 1. Merge into `main` with `--no-ff`

```sh
git checkout main
git merge --no-ff <branch> -m "Merge <ID>: <one-line summary>"
```

Every merge in the history is a `--no-ff` merge commit named `Merge <ID>: ...`
(for example `5e1cf9c Merge HARD-03: ...`, `f748267 Merge HARD-02: ...`).

Two variants are in use:

| Variant | Where the version bump lives | Used for |
|---|---|---|
| A. Release commit on `main` after the merge | separate commit `vX.Y.Z: ...` on `main` right after `Merge ...` | v0.7.15, v0.7.16, v0.7.17, v0.7.18 |
| B. Release commit on the branch | the branch carries a `vX.Y.Z: ...` commit; `Merge vX.Y.Z: ...` brings it to `main` | v0.7.9 to v0.7.14; with a PR and green CI on the PR first for v0.7.10 (PR #5), v0.7.11 (PR #6), v0.7.14 (PR #7) |

The PR runs the same Tests workflow (`pull_request` trigger) before anything reaches
`main`. The @cto rule since 02.11 asks for it ("branch -> PR -> green CI on the PR ->
merge"), because a suite that passes on macOS is not proof for the Linux runner
(v0.7.13: 392 MB on macOS, 499.75 MB in CI, red `main`). v0.7.14 followed it; v0.7.15
to v0.7.18 used variant A without a PR. [VERIFY: which variant is the rule from now on.]

For variant B:

```sh
git push -u origin <branch>
env -u GITHUB_TOKEN gh pr create --base main --head <branch> --title "vX.Y.Z: ..." --body "..."
# wait for the Tests run of the PR to be green, then merge --no-ff as above and push main
```

## 2. Release commit `vX.Y.Z: <summary>`

One commit touches exactly these four files (see `0acbd0c`, `4649b11`):

1. **`version.py`**: `APP_VERSION = "X.Y.Z"`. Single source of the version: OpenAPI,
   `/meta/version`, report provenance and the asset cache-buster read it
   (`tests/test_report_review_2026_09_18c.py::test_one_version_everywhere`).
2. **`README.md`**: the roadmap line `**vX.Y.Z (current):** ...` (and module or rule
   counts if they changed).
3. **`web/index.html`**: every `?v=` on the `.js` and `.css` assets set to the new
   version; all assets share one cache-buster, whether they changed or not.
   `test_asset_cache_version_follows_the_app_version` fails if one `?v=` differs from
   `version.py`. New JS/CSS files also need the `JS_FILES` / `CSS_FILES` whitelist in
   `api/main.py`.
4. **`CHANGELOG.md`**: a new section on top,
   `## [vX.Y.Z] – YYYY-MM-DD (<short title>)`, grouped by area (`### Security Tools`,
   `### Platform`, `### Tests`, ...), written for users.

Commit message pattern:

```
vX.Y.Z: <summary>

Release step for <ID> (reviewed by @ciso, <verdict>):
- version.py, README roadmap line and every ?v= asset in web/index.html -> X.Y.Z.
- CHANGELOG [vX.Y.Z]: <what changed>.

Tests: <N> passed, <M> skipped.
```

Run the full suite again after the bump (the version tests read the edited files).

Patch number: +1 per release (0.7.17 -> 0.7.18). [VERIFY: no written rule for minor
bumps; 0.6.x -> 0.7.0 is the only one in recent history.]

## 3. Push -> GitHub Actions tests -> Render deploy hook

```sh
git push origin main
sh scripts/dev/ci_status.sh     # waits for the Tests run of HEAD; exit 0 = green, 1 = red
```

What happens (`.github/workflows/tests.yml`):

1. A push to `main` starts **Tests**: clean Ubuntu runner, Python 3.11,
   `pip install -r requirements.txt`, `pytest tests/ -v`, with
   `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python`, `CVE_WARMUP_SYNC=0` and
   `CHEATSHEET_BROWSER_REQUIRED=1`.
2. Only when `pytest` is green, the `deploy` job (push to `main` only) calls the
   Render deploy hook (`secrets.RENDER_DEPLOY_HOOK_URL`) with `&ref=<GITHUB_SHA>`, so
   Render builds exactly that commit. A missing secret fails the job instead of passing
   silently.
3. Render builds the Docker image; the Dockerfile writes the build time to `BUILD_TIME`,
   which `/meta/version` reports as `build_time`.

A red run deploys nothing. `ci_status.sh` exists because five releases (v0.6.52-56)
went out on 2026-09-18 with CI red while nobody looked at Actions.

The weekly `Refresh Known Affected lists` workflow commits `data: ...` to `main` as
`github-actions[bot]`. Those commits have no Tests run of their own in the run list and
are not deployed by themselves; production picks them up with the next release.
[VERIFY: that a push with the workflow's `GITHUB_TOKEN` never starts `tests.yml`.]

## 4. Verify on production

```sh
curl -s https://netdevops-tools.thebackroom.ai/meta/version
```

`version` must be the new `X.Y.Z` and `build_time` after the push. Render needs a few
minutes after the green run; until then the old version answers. Then a smoke test of
the changed feature against production (for v0.7.18: Hardening Audit, rule 1.2.12 FAIL
on `aes256-cbc` + `dh min size 1024`). For UI changes, `scripts/dev/ui_smoke.py`
drives headless Chrome against a local server before the release.

Record in the backlog row: merge hash, release hash, CI run id, `/meta/version` value
and the smoke result.

## 5. Rollback

There is no rollback in the history yet; nothing below has been exercised. [VERIFY all]

- **Code (preferred, keeps CI in the path):** revert the merge on `main` and push; CI
  runs and the deploy job releases the reverted commit.

  ```sh
  git revert -m 1 <merge-hash>      # and the release commit, if variant A
  git push origin main
  sh scripts/dev/ci_status.sh
  curl -s https://netdevops-tools.thebackroom.ai/meta/version
  ```

  The revert brings back the previous `version.py`, so `/meta/version` shows the old
  number. [VERIFY: whether to bump forward instead (vX.Y.Z+1 that removes the change)
  so the version never goes backwards.]
- **Render panel:** the README names a Manual Deploy in the Render panel for an urgent
  fix with red tests. Render also offers a rollback to an earlier deploy. [VERIFY: both
  untested on this service; a panel deploy bypasses CI, and `main` no longer matches
  production until the code is reverted too.]
