# Release checklist

Every reader release uses this repository and must use the same firmware version in `esphome/CHANGELOG.md`, the `firmware-vX.Y.Z` Git tag, and the GitHub release title.

1. Start from a clean branch based on the current `main`.
2. Copy `esphome/secrets.example.yaml` to `esphome/secrets.yaml` and replace the API-key placeholder with a valid base64 test key.
3. From the repository root, run `esphome -s name_store_component_source components compile esphome/display-reader.example.yaml` and `esphome compile esphome/reader-only.example.yaml` with the ESPHome version pinned in `.github/workflows/ci.yml`.
4. Run `git diff --check` and confirm that no device secrets, local entity IDs, network addresses, or build output are tracked.
5. Test display, fingerprint, and touch behavior on the reference hardware when the release changes those paths.
6. Add the matching version heading to `CHANGELOG.md` and review the public documentation.
7. Merge the reviewed change into `main` only after CI passes.
8. Create and push an annotated `firmware-vX.Y.Z` tag at the merge commit.
9. Publish the matching GitHub release from the changelog entry.
10. Verify that the release archive contains `esphome/access-reader.yaml`, `esphome/reader-only.yaml`, both example wrappers, `esphome/components/fingerprint_name_store/`, the example secrets, and the integration documentation without a real `secrets.yaml` file.

Do not move an existing public tag. Publish a new patch version if a released artifact needs correction.
