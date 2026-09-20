---
name: release
description: Prepare and commit a Session Sniffer release by updating the version in pyproject.toml with the current UTC build timestamp, incrementing the RC or final version as requested, validating the change, and creating the release commit.
---

# Session Sniffer Release

Use this skill when the user wants to prepare and commit a new Session Sniffer release or release candidate.

## Release Procedure

1. Inspect the Git working tree before making changes.
2. Do not modify or discard unrelated user changes.
3. Read the current `version` from `pyproject.toml`.
4. Ask the user whether this is:
   - a new release candidate (`RC`), or
   - a final release.
5. Generate the current UTC timestamp in the format:
   - build timestamp: `YYYYMMDD.HHMM`
   - full UTC timestamp: `YYYY-MM-DDTHH:MM:SSZ`
6. Update the `version` in `pyproject.toml`.
7. For an RC:
   - increment the existing `rc.N` number by one;
   - preserve the existing `X.Y.Z` version.
8. For a final release:
   - remove the `rc.N` suffix;
   - preserve the requested `X.Y.Z` version.
9. Always append the new UTC build timestamp:
   `+YYYYMMDD.HHMM`
10. Review the resulting diff.
11. Run the relevant project validation before committing.
12. Show the user:
   - previous version,
   - new version,
   - changed files,
   - validation performed.
13. Create exactly one version-bump commit using:

   `build: bump version to <new-version>`

14. Do not amend, reset, rebase, force-push, or otherwise rewrite Git history.

## Version Format

The expected version format is:

`vMAJOR.MINOR.PATCH+YYYYMMDD.HHMM`

or for release candidates:

`vMAJOR.MINOR.PATCHrc.N+YYYYMMDD.HHMM`

Examples:

`v1.5.0rc.45+20260909.2017`

`v1.5.0+20260909.2017`

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

The version-bump commit should contain only the intended release-version changes.

Do not create a commit if validation fails.

## Validation

Use the project's existing validation configuration in `pyproject.toml`.

For a version-only change, use the smallest relevant validation available.

If dependencies, resources, packaging configuration, or other release-sensitive files are also changed, broaden validation appropriately.

Never claim validation was performed unless it was actually performed.

## Important

The version timestamp represents the current UTC time.

Do not use local time.

Do not manually invent or reuse a timestamp.

Do not silently change unrelated files.

Do not automatically push the commit.
