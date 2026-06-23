PYTHON ?= .venv/bin/python
CARGO_MANIFEST := native/assure-kernel/Cargo.toml

.PHONY: bootstrap test benchmark independent-benchmark dense-crossing frozen-region proposal-readiness completion-audit verify full campaign theory supply-chain

bootstrap:
	python3 -m venv .venv
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt -c requirements-lock.txt

test:
	$(PYTHON) -m unittest -v test_assure_core.py test_native_kernel.py

benchmark:
	cargo run --quiet --release --manifest-path $(CARGO_MANIFEST) -- benchmark 250000

independent-benchmark:
	$(PYTHON) tools/independent_benchmark.py

dense-crossing:
	$(PYTHON) dense_crossing_campaign.py

frozen-region:
	$(PYTHON) frozen_region_campaign.py

proposal-readiness:
	$(PYTHON) proposal_readiness.py

completion-audit:
	$(PYTHON) completion_audit.py

verify:
	$(PYTHON) tools/verify.py

full:
	$(PYTHON) tools/verify.py --full

campaign:
	$(PYTHON) tools/verify.py --full --campaign

theory:
	$(PYTHON) theory_campaign.py
	$(PYTHON) -m unittest -v test_theory_campaign.py

supply-chain:
	$(PYTHON) tools/generate_supply_chain.py
