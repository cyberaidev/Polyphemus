# Contributing to Polyphemus

Thanks for your interest! Polyphemus is a secure Amazon Bedrock RAG **reference**.
Contributions should keep it **offline-first**, **fully green**, and **honest**
about what each control does and does not prove.

## Ground rules

1. **Offline-first.** Everything must run with `POLYPHEMUS_MODE=mock` and no AWS
   credentials or network. `boto3` must never be imported in mock mode
   (`tests/test_no_boto3_in_mock.py` enforces this). The `aws`-mode clients are
   reference stubs; do not make the pipeline depend on them.
2. **Keep it green.** Every change must pass lint, type-check, and the full test
   suite (see the gate below) before you open a PR.
3. **Code is the source of truth for docs.** If you change pipeline behavior,
   update the docs, the Mermaid diagram, and regenerate the architecture SVG in
   the same PR so they never drift.
4. **Don't overclaim.** Security docs must match the code. In particular, be
   precise about the [mock-mode limitations](README.md#limitations-of-mock-mode).

## The gate (run this before every PR)

```bash
make setup        # one-time: create venv + install runtime + dev deps
make lint         # ruff + black --check
make typecheck    # mypy src
make test         # pytest, mock mode
make demo         # run the 4 scenarios (doubles as a smoke test; must exit 0)
```

If you touched the architecture diagram spec (`scripts/render_architecture.py`)
or any pipeline stage ordering, also run:

```bash
make render-diagram
git diff --exit-code docs/architecture.svg   # must be clean — never hand-edit the SVG
```

### Pre-commit (optional but recommended)

```bash
pip install pre-commit      # requires network the first time
pre-commit install
pre-commit run --all-files
```

The hooks in `.pre-commit-config.yaml` are `repo: local` — they invoke the
ruff/black/mypy already installed in your environment and mirror the Makefile, so
they run offline once `pre-commit` itself is installed.

## Style

- Python 3.10+; formatting by **black** (line length 100), linting by **ruff**,
  types checked by **mypy** (`src` is fully typed; see `py.typed`).
- Prefer small, well-documented modules with clear docstrings explaining the
  *security intent*, not just the mechanics.
- New behavior needs a test. New controls need a test **and** a doc mapping in
  `docs/SECURITY_CONTROLS.md`.

## Reporting security issues

Please do **not** file public issues for exploitable findings. See
[`SECURITY.md`](SECURITY.md) for private disclosure.

## License

By contributing you agree that your contributions are licensed under the
project's [Apache-2.0](LICENSE) license.
