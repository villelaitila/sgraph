# Releasing

Releases are performed by `scripts/release.py`. That script is the specification
of the procedure as well as its implementation: the order of the steps, the
preconditions it refuses to start without, and the points at which it stops to
ask are all defined there rather than restated here, so this document cannot
drift out of agreement with what actually runs.

Prerequisites — build and upload tooling, PyPI credentials, `gh` — and the exact
invocations are documented in [`scripts/README.md`](scripts/README.md).

## The shape of a release

A release happens in two phases, with a human decision between them.

1. **Propose.** The version is bumped and the change goes out as a pull request,
   so a release is reviewed like any other change.
2. **Complete.** Once that pull request is merged, the tag is pushed, the
   distribution is built and uploaded, and a GitHub release is created.

The gap between the two is deliberate. Nothing reaches PyPI from a version bump
that has not been merged first.

## Before starting

`main` should be in sync with `upstream/main` and the suite should be green.
The script validates its own preconditions and refuses to start rather than
failing after the tag is pushed, but those checks answer "can this run", not
"is this what we mean to publish" — that judgement is yours.

There is a dry run. A release is a good place to use it.

## When something goes wrong

A PyPI upload cannot be undone or replaced. A mistake is corrected by releasing
a further version, never by repairing the published one, which is why the script
asks for explicit confirmation before it uploads.
