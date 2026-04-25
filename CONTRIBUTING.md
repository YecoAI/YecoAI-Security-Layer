# Contributing to YecoAI Security Layer

First off, thank you for considering contributing to the YecoAI Security Layer! It's people like you that make the open source community such an amazing place to learn, inspire, and create.

## Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone the project** to your own machine.
3.  **Install the dependencies** locally:
    ```bash
    pip install -e ".[all,test]"
    ```
4.  **Run tests** to ensure everything is working:
    ```bash
    export PYTHONPATH=src
    python -m unittest discover -s tests
    ```

## Submitting a Pull Request

1.  Create a new branch for your feature or bugfix: `git checkout -b feature/my-awesome-feature`.
2.  Make your changes and write tests for them.
3.  Ensure that the test suite passes.
4.  Commit your changes with clear, descriptive commit messages.
5.  Push your branch to your fork: `git push origin feature/my-awesome-feature`.
6.  Open a Pull Request against the `main` branch of the original repository.

## Coding Standards

*   Follow standard Python style conventions (PEP 8).
*   Include type hints for new functions and classes.
*   Document any new features or API changes in the README or relevant documentation.
*   Ensure backward compatibility where possible.

## Reporting Bugs

If you find a bug, please open an issue with:

*   A clear and descriptive title.
*   A step-by-step reproduction of the bug.
*   Expected behavior vs. actual behavior.
*   The version of Python and the operating system you are using.
