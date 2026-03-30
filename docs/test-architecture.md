# Functional Test Architecture

## Goals

- Keep functional coverage close to the PostgreSQL protocol and trace output behavior that users consume.
- Avoid requiring root, eBPF attachment, or a live PostgreSQL process for the base suite.
- Leave a clear expansion path for future live integration coverage.

## Layers

### 1. Deterministic functional core

`PgTraceSession` in `pg_trace_session.{h,cpp}` owns:

- frontend/backend PostgreSQL wire-protocol parsing
- query queueing and correlation
- phase/operator/step/wait event aggregation
- final trace rendering

This layer is pure userspace logic and is the primary regression surface. The first test suite targets this layer directly.

### 2. Runtime adapter

`pg_probe.cpp` is now the runtime adapter. It is responsible for:

- finding PostgreSQL PIDs
- loading and attaching BPF programs
- polling the ring buffer
- forwarding events into `PgTraceSession`
- printing rendered query traces

This keeps probe lifecycle concerns separate from protocol semantics.

### 3. Future live integration tests

A later phase can add an opt-in integration lane that:

- boots a disposable PostgreSQL instance
- runs SQL fixtures
- executes `sniper` with real probe attachment
- verifies rendered output against snapshots or focused assertions

That lane should stay separate from the default developer suite because it will need elevated privileges and host kernel support.

## Current Suite

`tests/functional/pg_trace_session_test.cpp` covers:

- simple-query batch splitting across SQL edge cases
- extended protocol `Parse` / `Bind` / `Execute` flow
- rendered traces with phases, operators, scan steps, and lwlock waits

This is a fast component-functional lane. It validates the behavior users care about, but it does not boot PostgreSQL or attach BPF probes.

## Live Functional Lane

`tests/functional/run_live_functional_test.sh` is the real end-to-end harness. It:

- initializes a disposable PostgreSQL cluster
- starts PostgreSQL on a private Unix socket
- launches the real `sniper` binary
- executes SQL through `psql`
- asserts on the emitted trace output

The script requires the PostgreSQL service account name as its first argument so the harness does not need to guess which OS user should own the disposable cluster.

This lane is opt-in and should be enabled only on hosts that can run BPF attachment successfully.

## Execution

Configure:

```bash
cmake -S . -B build
```

Enable the live lane when needed:

```bash
cmake -S . -B build \
  -DSNIPER_ENABLE_LIVE_FUNCTIONAL_TESTS=ON \
  -DSNIPER_LIVE_TEST_PG_OS_USER=postgres
```

Build the functional suite only:

```bash
cmake --build build --target sniper_functional_tests
```

Run:

```bash
ctest --test-dir build --output-on-failure
```

Manual invocation:

```bash
sudo PATH=/usr/local/pg15/bin:$PATH \
  ./tests/functional/run_live_functional_test.sh postgres ./build/sniper
```
