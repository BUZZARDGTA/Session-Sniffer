---
name: release
description: Prepare and commit a Session Sniffer release by updating the version in pyproject.toml with the current UTC build timestamp, incrementing the RC or final version as requested, synchronizing uv.lock via uv lock, validating the change, and creating the release commit.
---

# Session Sniffer Release

Use this skill when the user wants to prepare and commit a new Session Sniffer release or release candidate.

## Release Procedure

1. Inspect the Git working tree before making changes.
2. Do not modify or discard unrelated user changes.
3. Read the current `version` from `pyproject.toml`.
4. Check whether the current version has already been published/tagged on GitHub (`git ls-remote --tags origin` or local tags matching the version prefix):
   - If NOT tagged/published on GitHub: do NOT increment the RC or version number; only update the build timestamp.
   - If ALREADY tagged/published on GitHub: ask the user whether this is a new release candidate (`RC`) or a final release.
5. Generate the current UTC timestamp in the format:
   - build timestamp: `YYYYMMDD.HHMM`
   - full UTC timestamp: `YYYY-MM-DDTHH:MM:SSZ`
6. Update the `version` in `pyproject.toml`:
   - If unpublished: preserve the existing version prefix (e.g. `v1.5.0rc.69`) and update only the build timestamp.
   - For a new RC: increment the existing `rc.N` number by one, preserving `X.Y.Z`.
   - For a final release: remove the `rc.N` suffix, preserving `X.Y.Z`.
   - Always append the new UTC build timestamp: `+YYYYMMDD.HHMM`
7. Synchronize `uv.lock` immediately:
   - Run `uv lock` to rebuild/update the `session-sniffer` version in `uv.lock`.
   - Enforce CRLF (`\r\n`) line endings on `uv.lock` (since `uv` outputs LF line endings by default).
   - Run `uv lock --check` to verify the lockfile is completely synchronized.
8. Review the resulting diff (both `pyproject.toml` and `uv.lock` should reflect the new version).
9. Run the release-specific validation before committing. For version-only changes, use `uv lock --check` and CRLF line-ending verification for `pyproject.toml` and `uv.lock`; do not run the full `python code_quality_checks.py` suite unless the release also includes significant code, dependency, resource, or packaging changes.
10. Verify CRLF (`\r\n`) line endings on all modified files, especially `uv.lock` and `pyproject.toml`.
11. Show the user:
    - previous version,
    - new version,
    - changed files (`pyproject.toml`, `uv.lock`),
    - validation performed.
12. Create exactly one version-bump commit containing both `pyproject.toml` and `uv.lock` using:

   `build: bump version to <new-version>`

13. Ensure the version-bump commit is pushed before creating any GitHub tag or release. The release tag MUST match `version` in `pyproject.toml` exactly.
14. Do not amend, reset, rebase, force-push, or otherwise rewrite Git history.

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

Use the project's existing validation configuration in `pyproject.toml`.

For a version-only change, use the smallest relevant validation available:
- Run `uv lock --check` to ensure `uv.lock` is strictly up to date.
- Verify CRLF (`\r\n`) line endings on both `pyproject.toml` and `uv.lock`.

If dependencies, resources, packaging configuration, or other release-sensitive files are also changed, broaden validation appropriately.

Never claim validation was performed unless it was actually performed.

## Important

The version timestamp represents the current UTC time.

Do not use local time.

Do not manually invent or reuse a timestamp.

Do not silently change unrelated files.

Do not automatically push the commit.
