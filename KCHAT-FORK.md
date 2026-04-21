# KChat Fork Notes

Upstream repository: https://github.com/openmls/openmls
Pinned tag: openmls-v0.8.0
Pinned commit: 6b85f0edc560b4fe0f5b9266092947a774614f3f

Rules for this fork:
- Keep legacy `MlsGroup::load(...)` semantics unchanged.
- Add KChat-specific behavior through additive paths only.
- Prefix fork-local comments with `KCHAT:`.
- Prefer small, topic-focused diffs for easier upstream rebasing.
