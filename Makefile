VENV=.venv
PYTHON=$(VENV)/bin/python3

.PHONY: venv
venv: $(VENV)/bin/activate

.PHONY: dev
dev: venv
	uv run app.py