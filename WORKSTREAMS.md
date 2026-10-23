# Workstreams

Each workstream has its own top-level folder named `ws-<id>-<slug>/`. Code, docs and assets for that workstream live inside its folder. Anything shared by more than one workstream goes in `shared/` (create it when it's first needed).

| ID | Workstream | Folder | Leader | Parent issue |
|---|---|---|---|---|
| WS-10 | Integrity | [`ws-10-integrity/`](ws-10-integrity/) | @sapna0310 | [#18](https://github.com/owasp-aibom-project/aibom/issues/18) |

Other workstreams are tracked in the [project sheet](https://docs.google.com/spreadsheets/d/1NuvxcZpPBe73OSWoQO9NKjTBpRl0ree_oZKYEWCkY84/edit) and will get a folder here when they start committing to the repo.

## Contributing to a workstream

1. Pick or create an issue under the workstream's parent issue.
2. Create a branch named `ws-<id>/<short-description>`, for example `ws-10/integrity-checker-cli`.
3. Commit only inside the workstream's folder unless the change is genuinely shared.
4. Open a pull request against `main` and put `Closes #<issue>` in the description so the issue closes when the PR merges.
5. The workstream leader is requested as a reviewer automatically through [`.github/CODEOWNERS`](.github/CODEOWNERS) and approves the merge.

## Adding a new workstream

Open one pull request that:

- creates `ws-<id>-<slug>/` with a `README.md` describing scope, leader and folder layout (copy `ws-10-integrity/README.md` as a starting point),
- adds a line for the folder and its leader's GitHub username to `.github/CODEOWNERS`,
- adds a row to the table above.

Nothing existing needs to move.
