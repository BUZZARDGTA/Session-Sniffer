---
name: release
description: Prepare, commit, and push a Session Sniffer release by updating the version in pyproject.toml with the current UTC build timestamp, incrementing the RC or final version as requested, synchronizing uv.lock via uv lock, validating the change, creating the release commit, pushing the branch to GitHub, and generating a synthesized user-facing changelog since the previous release.
---

# Session Sniffer Release

Use this skill when the user wants to prepare and commit a new Session Sniffer release or release candidate.

## Release Procedure

1. Inspect the Git working tree before making changes.
2. Run the release helper script in check mode to inspect `pyproject.toml`, published GitHub tags, and the current UTC timestamp:
   `python .agents/skills/release/scripts/prepare_release.py --check`
   (See [prepare_release.py](./scripts/prepare_release.py).)
3. Check whether the current version has already been published/tagged on GitHub (`is_published_on_github` from `git ls-remote --tags origin` or local tags matching the version prefix):
   - If NOT tagged/published on GitHub: do NOT increment the RC or version number; only update the build timestamp.
   - If ALREADY tagged/published on GitHub: ask the user whether this is a new release candidate (`RC`) or a final release.
4. Run [prepare_release.py](./scripts/prepare_release.py) to generate the current UTC timestamp (`YYYYMMDD.HHMM` / `YYYY-MM-DDTHH:MM:SSZ`), update `version` in `pyproject.toml`, run `uv lock`, enforce CRLF (`\r\n`) line endings on both `pyproject.toml` and `uv.lock`, and verify synchronization via `uv lock --check`:
   - If unpublished: `python .agents/skills/release/scripts/prepare_release.py --mode timestamp` (preserves the existing version prefix, e.g. `v1.5.0rc.69`, and updates only `+YYYYMMDD.HHMM`).
   - For a new RC: `python .agents/skills/release/scripts/prepare_release.py --mode rc` (increments the existing `rc.N` number by one, preserving `X.Y.Z`, and appends `+YYYYMMDD.HHMM`).
   - For a final release: `python .agents/skills/release/scripts/prepare_release.py --mode final` (removes the `rc.N` suffix, preserving `X.Y.Z`, and appends `+YYYYMMDD.HHMM`).
5. Review the resulting diff (both `pyproject.toml` and `uv.lock` should reflect the new version).
6. Run the release-specific validation before committing (see **Validation** below).
7. Create exactly one version-bump commit containing both `pyproject.toml` and `uv.lock` (see **Commit** below).
8. Push the current branch to GitHub (`git push`) immediately after creating the version-bump commit so `origin` already contains the updated `pyproject.toml` and `uv.lock` before the user publishes the GitHub release/tag. The release tag MUST match `version` in `pyproject.toml` exactly.
9. Show the user:
   - previous version,
   - new version,
   - changed files (`pyproject.toml`, `uv.lock`),
   - validation performed and confirmation that the branch was pushed to GitHub,
   - a copy-ready **GitHub Release Tag** in its own fenced code block (the exact `version` from `pyproject.toml`, e.g. `v1.5.0rc.93+20261027.2106` — never the PEP 440-normalized `uv.lock` version `1.5.0rc93+...`),
   - a copy-ready **GitHub Release Title** in its own fenced code block (`<version-without-build-metadata> - YYYY/MM/DD (HH:MM)`),
   - a synthesized **user-facing changelog** from the previous release to `HEAD` (following the **User Changelog** rules below).

## User Changelog

Always include a concise, well-structured user-facing changelog covering all net changes between the previous published release tag (or previous `build: bump version` commit) and `HEAD`.

### Synthesizing the Net Final State (Diff-First, Never Commit-Message-First)

Do **not** mechanically list, paraphrase, or trust commit subject lines (`git log`). Commit messages frequently describe intermediate designs, sub-features that were later removed before `HEAD`, or internal fixes to unpublished code from earlier in the same cycle.

Instead, follow a strict **diff-first workflow**:
1. Inspect the net code diff (`git diff <prev-release>..HEAD -- src/ resources/`) and the actual code at `HEAD` as the **sole source of truth** for what changed compared to `<prev-release>`.
2. Use `git log <prev-release>..HEAD` **only** to attribute commit SHAs to the net changes you have already verified in `git diff <prev-release>..HEAD`.

Apply these mandatory rules to every entry:

- **Verify every sub-item of a commit against `git diff <prev-release>..HEAD`**: When a commit message mentions multiple items (e.g. `"add visual indicators, ON/OFF toggle pill, and context menu toggle"`), inspect `git diff <prev-release>..HEAD` to confirm each item still exists in `HEAD`. If one part (such as a context menu toggle) was later removed or reworked in a subsequent commit before `HEAD`, omit that removed part completely—never copy it from the earlier commit's subject line.
- **Consolidate multi-commit work without leaking intermediate fix details**: If a feature or change was introduced after `<prev-release>` and later refined, fixed, guarded, or tweaked in subsequent commits during the same release cycle, merge all contributing commit links into a single cohesive entry describing **only the final user-facing behavior**. Do not append internal stabilization clauses or intermediate commit-subject phrasing (e.g. `"with automatic operator flipping..."`, `"concurrent file-read retry handling..."`, or `"guard unresolved..."`) to the changelog description.
- **Drop transient intermediate bugs (`### Fixed` is strictly for bugs present in `<prev-release>`)**: Every entry under `### Fixed` must fix a bug that existed in `<prev-release>`. If a commit (`fix(...)`) fixed a bug, regression, or edge case that was introduced *after* `<prev-release>` by an earlier commit in the same `<prev-release>..HEAD` range, **never** list it under `### Fixed` and never describe the transient bug—at most, include its commit link alongside the parent feature/change entry.
- **Drop reverted or removed experiments**: If a feature, UI control, or refactor was added after `<prev-release>` and later reverted or removed before `HEAD`, omit it completely when its net change vs. `<prev-release>` is zero.
- **Filter internal noise**: Omit purely internal housekeeping commits (e.g. `.gitignore` tweaks, agent/skill config edits, lockfile/dependency bumps, version bumps, type-annotation-only fixes, or pure code formatting) that have no user-visible behavior, stability, or performance impact.
- **Verify exact integrations, filenames, paths, and UI labels from `HEAD` and `README.md`**: Never guess or rely on outdated/archived conventions (e.g. all settings and UserIP databases use `.json`, not `.ini`; cross-check active plugins/integrations against `README.md` and `HEAD`). Check the actual diff/source at `HEAD` to cite exact file formats, log paths, and data sources.
- **Group by category**: Organize entries under relevant headings such as `### Added`, `### Changed`, `### Fixed`, `### Performance`, or `### Removed` (include only categories that have entries).
- **Clickable GitHub commit links**: Format every referenced commit hash as a clickable Markdown link to the repository commit on GitHub: `` [`<short-sha>`](https://github.com/BUZZARDGTA/Session-Sniffer/commit/<full-sha>) ``. When a consolidated entry spans multiple commits, link each contributing commit (e.g. ``([`7c0bab5`](https://github.com/BUZZARDGTA/Session-Sniffer/commit/7c0bab5f80a2b7b824883b713801af53921d6303), [`6841708`](https://github.com/BUZZARDGTA/Session-Sniffer/commit/68417080625ab90e9fb92ae4902736c05b318e8d))``).
- **Copy-ready raw Markdown block**: Provide the changelog in a fenced ````markdown` code block so it can be copied in one click into the GitHub Release notes, where `.github/workflows/build.yml` (`notify-discord`) automatically forwards it to the Discord release webhook once the Windows, Linux, and macOS binaries finish compiling.

### Pre-Output Changelog Audit Checklist

Before presenting the changelog to the user, audit every bullet and sub-clause against these three checks:
1. **Net-Diff Check**: Does every feature, UI element, or behavior mentioned in this sentence actually exist in `git diff <prev-release>..HEAD` at `HEAD`, or did it come from an earlier commit subject line that was later modified/removed?
2. **Baseline Bug Check**: For every item in `### Fixed`, did that bug exist in `<prev-release>`? (If it was fixing code introduced after `<prev-release>`, remove it from `### Fixed`.)
3. **No Intermediate Mechanics Check**: Does any feature bullet include internal implementation/fix phrasing copied from follow-up `fix(...)` commit subjects? (If so, strip the fix phrasing and keep only the clean user-facing description of the final feature.)

## Version Format

The expected version format is:

`vMAJOR.MINOR.PATCH+YYYYMMDD.HHMM`

or for release candidates:

`vMAJOR.MINOR.PATCHrc.N+YYYYMMDD.HHMM`

Examples:

`v1.5.0rc.45+20260909.2017`

`v1.5.0+20260909.2017`

## Unpublished / Untagged Releases

If the current version in `pyproject.toml` has not been published or tagged on GitHub (e.g. no remote tag exists matching the current version prefix, such as `v1.5.0rc.69`):
- Do NOT increment the version number or `rc.N` number.
- Retain the exact existing version prefix.
- Only update the UTC build timestamp (`+YYYYMMDD.HHMM`).

For example, if the current version is:

`v1.5.0rc.69+20260929.0504`

and `rc.69` was never tagged or published on GitHub, the next build timestamp update becomes:

`v1.5.0rc.69+<current UTC timestamp>`

## RC Releases

If the current version is:

`v1.5.0rc.44+20260908.1641`

the next RC must become:

`v1.5.0rc.45+<current UTC timestamp>`

Do not reuse the previous timestamp.

## Final Releases

If the current version is:

`v1.5.0rc.45+20260909.2017`

a final release of version `1.5.0` becomes:

`v1.5.0+<current UTC timestamp>`

Do not retain the `rc.N` suffix.

If the user intends a different `X.Y.Z` final version, confirm that version before changing the file.

## Commit

The commit subject must be:

`build: bump version to <new-version>`

For example:

`build: bump version to v1.5.0rc.45+20260909.2017`

The version-bump commit should contain only the intended release-version changes in `pyproject.toml` and `uv.lock`. Never commit a release version bump without its synchronized `uv.lock`.

Do not create a commit if validation fails.

## Validation

For a version-only change, use the smallest relevant validation available:
- Run `uv lock --check` to ensure `uv.lock` is strictly up to date.
- Verify CRLF (`\r\n`) line endings on both `pyproject.toml` and `uv.lock`.

Do not run the full `python code_quality_checks.py` suite unless the release also includes significant code, dependency, resource, packaging, or other release-sensitive changes; in that case broaden validation appropriately.

## Important

The version timestamp represents the current UTC time.

Do not use local time.

Do not manually invent or reuse a timestamp.

When `/release` is invoked, always push the branch to GitHub (`git push`) after creating the release commit so the remote branch is up to date before the GitHub release/tag is created.
