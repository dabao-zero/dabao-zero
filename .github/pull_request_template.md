## What and why

<!-- One or two sentences. Link the TASKS.md task or ADR this implements. -->

## Test evidence

<!-- What you ran (`make check`, `make frontend-check`) and the result. For a bug fix: the test that failed first. -->

## Guards proven

<!-- If this adds or changes a gate, check or safety rule: how you watched it fail (break it on purpose, confirm the right test goes red, restore non-destructively). Otherwise delete. -->

## Risk

<!-- Does it touch gates, signing, the publish path, secrets, migrations or a default? Is the new behaviour behind a flag that defaults to the old one? Migrations land alone. -->
