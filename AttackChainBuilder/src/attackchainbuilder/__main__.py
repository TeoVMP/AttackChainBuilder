"""Allow ``python -m attackchainbuilder`` execution."""

from attackchainbuilder.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
