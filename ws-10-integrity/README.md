# WS-10 Integrity

Standard, checks and tooling for verifying the integrity of an AIBOM.

- Leader: @sapna0310
- Parent issue: [#18 WS-10 -- Integrity](https://github.com/owasp-aibom-project/aibom/issues/18)

## Current work

| Issue | Task | Goes in |
|---|---|---|
| [#19](https://github.com/owasp-aibom-project/aibom/issues/19) | Build the Integrity Checker calculator | `src/`, `tests/` |
| [#20](https://github.com/owasp-aibom-project/aibom/issues/20) | Document the standard and checks for AIBOM integrity, with AIBOM branding | `docs/`, `assets/` |
| [#21](https://github.com/owasp-aibom-project/aibom/issues/21) | Publish the integrity check workbook, standard and tool | `docs/` |

## Layout

| Folder | What goes here |
|---|---|
| [`src/`](src/) | Source code for the Integrity Checker |
| [`tests/`](tests/) | Tests for the code in `src/` |
| [`docs/`](docs/) | The integrity standard, check definitions, workbook and user guides |
| [`assets/`](assets/) | Logos, images and diagrams used by the docs |

## How to contribute

Branch from `main` as `ws-10/<short-description>`, keep changes inside `ws-10-integrity/`, and open a pull request with `Closes #<issue>`. The workstream leader is requested as a reviewer automatically. See [WORKSTREAMS.md](../WORKSTREAMS.md) for the full flow.
