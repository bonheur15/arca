# Contributing to Arca

Arca is security-sensitive storage software. Keep changes narrow, preserve the published `/api/v1` contract, and include failure-path tests for every storage or authorization change.

## Local checks

```sh
make install-web
make check
```

Go changes should be formatted with `gofmt`. Frontend changes must pass TypeScript, Vitest, the production Vite build, keyboard review, and reduced-motion review. Storage changes should exercise a real temporary SQLite database and filesystem; authentication changes should use the fake WorkOS boundary unless running the opt-in staging suite.

Never commit real WorkOS credentials, session cookies, Magic Auth codes, public share codes, PATs, user files, or an `arca-data` directory. Do not hand-edit either generated OpenAPI type file; run `make generate`.

Report security issues privately as described in [SECURITY.md](SECURITY.md).

