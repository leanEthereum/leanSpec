---
name: client-test
description: Run leanSpec fixtures against a client implementation
---

# /client-test - Client Integration Testing

Run generated leanSpec test fixtures against a client implementation.

## Usage

`/client-test <client-name>` e.g. `/client-test ream`

## Steps

### 1. Check fixtures exist

Generated fixtures live at `fixtures/consensus/`. Verify it contains JSON files. If empty or missing, generate them:

```bash
uv run fill --fork=devnet --clean -n auto --scheme=prod
```

Fixtures for client testing must always use `--scheme=prod` (production signatures).

### 2. Clone or update client

Clone the client repo into `clients/` (gitignored). If already cloned, pull latest.

### 3. Sync fixtures

Remove old fixtures at the destination, then copy the contents of `fixtures/consensus/` to the destination (destination path is client-dependent).

### 4. Run tests

Run the test command from the client's test workdir (path is client-dependent). Show full output. Do not abort early on test failures.

If zero tests ran, warn that the client may need to update its test runner to scan the new devnet fixture path.

## Clients

### ream

- **Repo**: https://github.com/ReamLabs/ream.git
- **Fixture destination** (relative to repo root): `testing/lean-spec-tests/fixtures/devnet4`
- **Test workdir** (relative to repo root): `testing/lean-spec-tests`
- **Test command**: `cargo test --release --features lean-spec-tests`

### zeam

- **Repo**: https://github.com/blockblaz/zeam.git
- **Fixture destination** (relative to repo root): `leanSpec/fixtures/consensus` (leanSpec is a git submodule)
- **Test workdir** (relative to repo root): `.` (repo root)
- **Test commands** (run in order):
  1. `zig build spectest:generate --summary all` (generate Zig test wrappers from JSON fixtures)
  2. `zig build spectest:run --summary all` (run the spec tests)

### qlean-mini

- **Repo**: https://github.com/qdrvm/qlean-mini.git
- **Branch**: `spec/test-vectors` (test vector infrastructure is not on master)
- **Fixture destination** (relative to repo root): `tests/test_vectors/fixtures/consensus`
- **Test workdir** (relative to repo root): `.` (repo root)
- **Test commands** (run in order):
  1. `cmake --preset default` (configure)
  2. `cmake --build build -j` (build)
  3. `ctest --test-dir build -R test_vectors_test --output-on-failure` (run spec tests)
