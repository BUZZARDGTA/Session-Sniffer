---
name: release
description: Prepare and commit a Session Sniffer release by updating the version in pyproject.toml with the current UTC build timestamp, incrementing the RC or final version as requested, synchronizing uv.lock via uv lock, validating the change, creating the release commit, and generating a synthesized user-facing changelog since the previous release.
---

# Session Sniffer Release

Use this skill when the user wants to prepare and commit a new Session Sniffer release or release candidate.

## Release Procedure

1. Inspect the Git working tree before making changes.
2. Read the current `version` from `pyproject.toml`.
3. Check whether the current version has already been published/tagged on GitHub (`git ls-remote --tags origin` or local tags matching the version prefix):
   - If NOT tagged/published on GitHub: do NOT increment the RC or version number; only update the build timestamp.
   - If ALREADY tagged/published on GitHub: ask the user whether this is a new release candidate (`RC`) or a final release.
4. Generate the current UTC timestamp in the format:
   - build timestamp: `YYYYMMDD.HHMM`
   - full UTC timestamp: `YYYY-MM-DDTHH:MM:SSZ`
5. Update the `version` in `pyproject.toml`:
   - If unpublished: preserve the existing version prefix (e.g. `v1.5.0rc.69`) and update only the build timestamp.
   - For a new RC: increment the existing `rc.N` number by one, preserving `X.Y.Z`.
   - For a final release: remove the `rc.N` suffix, preserving `X.Y.Z`.
   - Always append the new UTC build timestamp: `+YYYYMMDD.HHMM`
6. Synchronize `uv.lock` immediately:
   - Run `uv lock` to rebuild/update the `session-sniffer` version in `uv.lock`.
   - Enforce CRLF (`\r\n`) line endings on `uv.lock` (since `uv` outputs LF line endings by default).
   - Run `uv lock --check` to verify the lockfile is completely synchronized.
7. Review the resulting diff (both `pyproject.toml` and `uv.lock` should reflect the new version).
8. Run the release-specific validation before committing (see **Validation** below).
9. Create exactly one version-bump commit containing both `pyproject.toml` and `uv.lock` (see **Commit** below).
10. Show the user:
    - previous version,
    - new version,
    - changed files (`pyproject.toml`, `uv.lock`),
    - validation performed,
    - a copy-ready **GitHub Release Tag** in its own fenced code block (the exact `version` from `pyproject.toml`, e.g. `v1.5.0rc.93+20261027.2106` — never the PEP 440-normalized `uv.lock` version `1.5.0rc93+...`),
    - a copy-ready **GitHub Release Title** in its own fenced code block (`<version-without-build-metadata> - YYYY/MM/DD (HH:MM)`),
    - a synthesized **user-facing changelog** from the previous release to `HEAD` (following the **User Changelog** rules below).
11. Ensure the version-bump commit is pushed before creating any GitHub tag or release. The release tag MUST match `version` in `pyproject.toml` exactly.

## User Changelog

Always include a concise, well-structured user-facing changelog covering all net changes between the previous published release tag (or previous `build: bump version` commit) and `HEAD`.

### Synthesizing the Net Final State (Not Commit-by-Commit)

Do **not** mechanically list or paraphrase every commit one by one. Instead, inspect both the commit history (`git log <prev-release>..HEAD`) and the net code diff (`git diff <prev-release>..HEAD`) to represent the **actual final state at the end of the release cycle**:

- **Consolidate multi-commit work**: If a feature or change was introduced in one commit and later refined, fixed, reworked, or optimized in subsequent commits during the same release cycle, merge them into a single cohesive entry describing the final behavior.
- **Drop transient intermediate bugs**: If a commit fixed a bug or regression that was introduced earlier *after* the previous release (within the same `<prev-release>..HEAD` range), do not list that fix as a standalone bug fix—only the net outcome compared to `<prev-release>` matters.
- **Drop reverted or removed experiments**: If a feature, change, or refactor was added and later reverted or removed before `HEAD`, omit it completely when the net change vs. `<prev-release>` is zero.
- **Filter internal noise**: Omit purely internal housekeeping commits (e.g. `.gitignore` tweaks, agent/skill config edits, version bumps, or pure code formatting) that have no user-visible behavior, stability, or performance impact.
- **Verify exact filenames, paths, and data sources from the code**: Never guess or rely on outdated conventions (e.g. all settings and UserIP databases use `.json`, not `.ini`). Check the actual diff/source to cite exact file formats, log paths, and data sources.
- **Group by category**: Organize entries under relevant headings such as `### Added`, `### Changed`, `### Fixed`, `### Performance`, or `### Removed` (include only categories that have entries).
- **Clickable GitHub commit links**: Format every referenced commit hash as a clickable Markdown link to the repository commit on GitHub: `` [`<short-sha>`](https://github.com/BUZZARDGTA/Session-Sniffer/commit/<full-sha>) ``. When a consolidated entry spans multiple commits, link each contributing commit (e.g. ``([`7c0bab5`](https://github.com/BUZZARDGTA/Session-Sniffer/commit/7c0bab5f80a2b7b824883b713801af53921d6303), [`6841708`](https://github.com/BUZZARDGTA/Session-Sniffer/commit/68417080625ab90e9fb92ae4902736c05b318e8d))``).
- **Copy-ready raw Markdown block**: Provide the changelog in a fenced ````markdown` code block so it can be copied in one click into the GitHub Release notes, where `.github/workflows/build.yml` (`notify-discord`) automatically forwards it to the Discord release webhook once the Windows, Linux, and macOS binaries finish compiling.

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

Do not automatically push the commit.
