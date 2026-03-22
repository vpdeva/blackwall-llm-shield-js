# Changesets

Use Changesets to manage package versioning and changelogs.

Typical flow:

1. Run `npm run changeset`
2. Describe the change and choose the version bump
3. Commit the generated markdown file in `.changeset/`
4. Merge to `main`

The release workflow will open or update a version PR. When that PR is merged, npm publish runs automatically.
