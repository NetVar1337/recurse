# Contributing to Recurse

Thanks for contributing. By opening a pull request you agree:

1. Your work is licensed under the Apache License, Version 2.0
   (see `LICENSE`, Section 5, inbound = outbound).
2. You accept the Contributor License Agreement:
   - Individuals: `CLA-INDIVIDUAL.md`
   - Companies submitting employee work: `CLA-CORPORATE.md`

The CLA bot will ask you to sign once on your first PR.
Corporate contributors: have an authorized signatory complete
`CLA-CORPORATE.md` (one signature covers listed employees).

## Intellectual property rules

- Only submit work you created or have rights to submit.
- If employed, confirm your employer allows it or has signed
  the Corporate CLA.
- Do not paste proprietary, GPL-incompatible, or crackme
  binaries into PRs. Crackmes are for local eval only
  (see `NOTICE`).
- Keep the native engine copyleft-free: no GPL/AGPL
  dependencies in `crates/recurse-static` native path.
  The `r2` backend stays an optional subprocess (see
  `docs/backends.md`).

## License headers

New Rust/TypeScript files should start with:

    SPDX-License-Identifier: Apache-2.0
