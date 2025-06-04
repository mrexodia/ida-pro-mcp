from .server.core import main as core_main


def main(argv: list[str] | None = None) -> None:
    """Launch the offline core."""
    core_main(argv)


if __name__ == "__main__":  # pragma: no cover
    main()
