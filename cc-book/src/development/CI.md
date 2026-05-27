# CI Builds via GNU make and GitHub Actions

## Contents

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Contents](#contents)
- [Make-based actions & workflows in `core-crypto`](#make-based-actions--workflows-in-core-crypto)
- [Generic `make` action](#generic-make-action)
  - [File Hashes of Dependencies](#file-hashes-of-dependencies)
  - [Artifact Caching](#artifact-caching)
- [Specialized `make` actions](#specialized-make-actions)

<!-- mdformat-toc end -->

## Make-based actions & workflows in `core-crypto`

Our CI pipeline is heavily driven by make rules (in the root [`Makefile`](../Makefile)). To avoid duplicating logic, the
CI uses small GitHub composite actions that invoke specific make targets with consistent artifact caching via GitHub
artifatcs.

The directory `.github/actions/make/` houses:

- A generic composite action ([`.github/actions/make/action.yml`](../.github/actions/make/action.yml))
- Specialized wrappers in subdirectories which call the generic action

The workflow file [`.github/workflows/pipeline.yml`](../.github/workflows/pipeline.yml) orchestrates CI jobs, and uses
those make actions in steps.

## Generic `make` action

This action produces an artifact which corresponds to a rule in the root [`Makefile`](../Makefile), or downloads it if
any subsequent workflow run already produced the artifact with unchanged prerequisites.

### File Hashes of Dependencies

The prerequisites of ceach artifact are defined in the [`Makefile`](../Makefile) itself. Each artifact that is produced
using this action, has a corresponding variable in the [`Makefile`](../Makefile), called `<target-name>-deps`, which
lists the artifact's dependencies.

The [`Makefile`](../Makefile) contains a wildcard rule that uses this variable to calculate an aggregated `sha256sum` of
all dependencies. This is then appended to the artifact key, identifying an artifact when downloading or uploading.

### Artifact Caching

Each caller of the generic `make` action must provide an artifact key, required to identify an artifact. This is
necessary downloading a previously produced artifact or uploading the artifact just produced. The aggregated `sha256sum`
(see above) is then appended to that key to ensure artifacts with different dependencies don't share a key.

In case an artifact was successfully downloaded, the action `touch`es them, because otherwise the checked out source
files would be newer than the downloaded artifacts. This is necessary because another subsequent call of this actions
for another rule might require that the downloaded artifact is newer than the source files.

Otherwise, the artifact is produced by calling `make <rule argument>`.

In both cases (artifact was downloaded or produced), the artifact is uploaded only if it hasn't been uploaded for this
workflow run of [`pipeline.yml`](../.github/workflows/pipeline.yml). This is relevant because the `make` action may be
called with the same parameters multiple times in a single workflow run.

## Specialized `make` actions

Since most artifacts (except those produced by a job representing a "leaf" in the make dependency tree) are reused
during the [`pipeline.yml`](../.github/workflows/pipeline.yml) workflow, the generic action is frequently called with
the same arguments. The parameters of the `make` action are the artifact key, the `make` rule, and the target path. To
avoid having to repeat the arguments when an artifact is reused, we're using sepcialized `make` actions, located in
subfolders of `.github/actions/make`. These specialized actions are parameterless, except for the github token, which
they just forward. The github token is needed to use the `gh` CLI on the runner machine.

Any reused artifact should have such a specialized action. Whenever a new artifact is introduced in the workflow and it
needs to be reused, an action should be added.
