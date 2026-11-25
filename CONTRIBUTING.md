# Contributing

* Python 3.11+, standard library plus PyYAML. Keep the dependency surface minimal.
* Run `python -m unittest discover -s tests -v` and `python -m unittest discover -s acceptance/tests -v`
  before opening a PR. CI runs both on Python 3.11-3.13, plus a Linux job that validates output
  with the pinned, checksum-verified ferrum-edge release and runs the loopback runtime acceptance
  (`acceptance/README.md`).
* A runtime case asserts claims only when it passes. Keep `outcome_kind` honest: a safe
  refusal is never a behavioral pass. Never loosen a probe expectation just to turn a run green.
* Every new mapping needs a positive test **and** a fail-closed test (what happens when the
  source uses an unsupported variant).
* Verify Ferrum behavior against Ferrum Edge source or docs before relying on it, and cite the
  file in `docs/mappings.md`. Unverifiable behavior goes under "Open questions".
* Fixtures must be original and synthetic. Never commit real configs, credentials, certificates,
  keys or logs; credential-like values in fixtures must be obviously fake (`test-only-...`).
* Never copy code or documentation text from Kong, NGINX, Traefik, Envoy, Istio or Ferrum.
  Write mappings from the documented behavior.
* Diagnostics and report messages must not contain input values; use `safe_label` for names
  and count secrets instead of printing them.
