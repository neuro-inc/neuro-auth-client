all: setup test

setup:
	pip install -U pip
	pip install -r requirements-dev.txt
	pre-commit install

lint: format
	mypy neuro_auth_client tests

format:
ifdef CI_LINT_RUN
	pre-commit run --all-files --show-diff-on-failure
else
	pre-commit run --all-files
endif


test:
	pytest -vv --cov neuro_auth_client --cov-report xml:.coverage.xml tests
