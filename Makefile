fmt:
	uv run isort .
	uv run black .
	uv run ruff check . --fix
	# todo - implement mypy & pylint
	# uv run -m mypy .
	# uv run pylint --output-format=colorized -j 0 src

verify:
	uv run isort . --check
	uv run black . --check
	uv run ruff check .
	# todo - implement mypy & pylint
	# uv run -m mypy .
	# uv run pylint --output-format=colorized -j 0 src