# Release checklist

Every Access Manager release must use the same version in the add-on manifest, changelog, Git tag, and GitHub release.

1. Start from a clean branch based on the current `main`.
2. Run:

   ```text
   python -m unittest discover -s tests -v
   node tests/check_ui.mjs
   git diff --check
   ```

3. Confirm that `access_manager/config.yaml` contains the new semantic version.
4. Add the matching version heading to `access_manager/CHANGELOG.md`.
5. Confirm that the repository contains no installation-specific entity IDs, people, network addresses, codes, tokens, or credentials.
6. Merge the reviewed change into `main`.
7. Create and push an annotated `vX.Y.Z` tag at the merge commit.
8. Publish the matching GitHub release from the changelog entry.
9. Refresh the repository in Home Assistant and verify that the add-on offers or installs the same version.
10. Verify `/health`, the existing data, and the sidebar panel through Home Assistant ingress on both desktop and the mobile app. Confirm that the new panel build appears without clearing either cache.

Home Assistant add-on auto-update only sees a release after the version in `access_manager/config.yaml` is available on the repository's default branch. Do not create the tag before that commit is on `main`.
