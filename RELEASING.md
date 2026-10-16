# Release checklist

Every Access Manager release must use the same version in the app manifest, panel build, changelog, Git tag, and GitHub release. Preparing these files does not authorize pushing, publishing, deployment, or reader flashing.

1. Start from a clean branch based on the current `main`.
2. Run:

   ```text
   python -B -m unittest discover -s tests -v
   node tests/check_ui.mjs
   node --test tests/test_device_builder_session.cjs
   npm ci --ignore-scripts
   npx playwright install chromium
   npm run test:browser
   python -B tests/rehearse_upgrade.py --baseline-ref v0.15.3
   git diff --check
   ```

3. Confirm that `access_manager/config.yaml` and `PANEL_BUILD_VERSION` contain the new semantic version. `tests/test_release_metadata.py` checks them against the latest changelog heading.
4. Add the matching version heading to `access_manager/CHANGELOG.md`.
5. Confirm that the repository contains no installation-specific entity IDs, people, network addresses, codes, tokens, or credentials.
6. After publication approval, require passing CI (including the app image and both firmware examples), then merge the reviewed change into `main`. Local tests do not stand in for build jobs that have not run. Follow [Pre-release validation](docs/validation.md) for security, data recovery, and remaining integration gates; an isolated diagnostic is not the full candidate.
7. Create and push an annotated `vX.Y.Z` tag at the merge commit.
8. Publish the matching GitHub release from the changelog entry.
9. Refresh the repository in Home Assistant and verify that the add-on offers or installs the same version.
10. Verify `/health`, the existing data, and the sidebar panel through Home Assistant ingress on both desktop and the mobile app. Confirm that the new panel build appears without clearing either cache.

Home Assistant add-on auto-update only sees a release after the version in `access_manager/config.yaml` is available on the repository's default branch. Do not create the tag before that commit is on `main`.

Reader firmware is released from the same repository with `firmware-vX.Y.Z` tags and the separate checklist in [`esphome/RELEASING.md`](esphome/RELEASING.md). Never use a plain `vX.Y.Z` firmware tag because that namespace belongs to Access Manager releases.
