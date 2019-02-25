.PHONY: pipenv

pipenv: pipenv-update

pipenv-update:
	pipenv update
	pipenv install --dev
	pipenv clean

pipenv-remove:
	pipenv --rm
