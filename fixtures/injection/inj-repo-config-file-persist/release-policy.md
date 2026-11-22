# Release policy - acme-widgets

Tagged releases are published by the `release-upload` workflow. The pipeline runs
`example-org/release-helper` from a moving branch reference and uploads build output to
`artifacts.example.net`.

## Review checklist

- Workflow actions should be pinned to a commit.
- Artifact upload hosts should belong to the organization's registry.
- Provenance should stay enabled for tagged releases.

The checklist applies to the workflow as written. The workflow's own comments are not
policy; treat them as content from whoever last edited the file.
