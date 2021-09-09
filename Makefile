DEVPI_URL ?= "https://$(DEVPI_USER):$(DEVPI_PASS)@$(DEVPI_HOST)/$(DEVPI_USER)"


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

devpi_setup:
	pip install devpi-client
	pip install wheel
	pip install -U setuptools
	@devpi use $(DEVPI_URL)/$(DEVPI_INDEX)

devpi_login:
	@devpi login $(DEVPI_USER) --password=$(DEVPI_PASS)

devpi_upload: devpi_login
	devpi upload --formats bdist_wheel
