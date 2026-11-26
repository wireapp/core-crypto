# Contributing to CoreCrypto

This repository is open-source, but not open-development. While we encourage third parties to audit and validate the
CoreCrypto implementation, all development is conducted in-house at Wire. Pull requests to this repository from
individuals not employed or contracted by Wire will not be accepted.

## Vulnerability and Bug Reporting

Vulnerabilities discovered should be sent to <mailto:vulnerability-report@wire.com>. See also:
<https://wire.com/en/vulnerability-reporting>, <https://wire.com/hubfs/security.txt>.

Bugs can be reported to <opensource@wire.com>; they will be forwarded to the CoreCrypto team. Include your Wire version
and platform, expected behavior, and encountered behavior at minimum. Include the CoreCrypto version, reproduction
steps, and relevant client logs if possible.

## In-House Development

The CoreCrypto team shares primary development responsibility for this repo. All development proceeds via a pull
request, and all pull requests must be approved by a member of this team.

The normal workflow for in-house feature requests and bug reports is via Jira. Tickets in the WPB space which are
assigned to both the "CoreCrypto" and "Discipline" components will show up in the team's queue and be triaged by the
CoreCrypto team. High-priority items should be discussed directly with CoreCrypto in any of the relevant Wire
conversations.

### Pull Requests

#### For Production

The CoreCrypto team is opinionated about the way we write our code. Contributions from within Wire but outside the CC
team are welcome, but it is rare for one to be accepted without a round or two of comments and suggestions.

All PRs intended for production in this repo must adhere to the
[CoreCrypto AI Policy](https://wearezeta.atlassian.net/wiki/x/EoDBx), which is summarized in [AGENTS.md](./AGENTS.md).

The [README](./README.md) has detailed instructions on setting up your dev environment, building, and testing.

Beyond that, here are some guidelines to ensure a smooth process:

- Base your work on `main`
- Rebase as required to keep history linear
- Use signed Conventional Commits
- Keep each commit focused on a single semantic change
- Ensure user-visible changes appear in the [book](cc-book/src/release_notes.md#unreleased)
- CI must be green for a PR to merge, but certain CI steps are known to be flaky; talk to the CC team if you are unsure
  if a failing test indicates flakiness or a problem in your PR.
- After approval, merge your own work with [`merge-pr`](https://github.com/wireapp/merge-pr)

#### Experimental

Experimental pull requests not intended to be merged are welcome. The normal use case for something like this is a proof
of concept, or just to exercise the full CI test suite.

- Open your PR as a draft.
- Mark the PR as "EXPERIMENTAL", "DO NOT MERGE", or similar.
- Close your PR when you're done with it.
- In a case like this, AI use is explicitly permitted, but a human will need to rewrite any library code in a new PR
  before it could be considered for inclusion.
