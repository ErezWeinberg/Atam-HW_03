# Atam-HW_03

Homework 3 for the course **Computer Organization and Programming (ATAM)**.

## Course Overview

The ATAM course (Computer Organization and Programming) focuses on the connection between software and hardware, and on how high-level programs are translated and executed in practice.

Core topics usually include:
- C program structure and interaction with the operating system
- Compilation, linking, and execution of binaries
- ELF file format and symbol tables
- System calls, processes, and fork/exec flow
- Register-level execution and calling conventions
- Debugging and runtime tracing with tools like `ptrace`

## Homework Goal (HW3)

In this assignment, you implement a tracing/debugging tool named `prf` that:
- Loads and parses an ELF file
- Finds a function address by symbol name
- Runs a target program under tracing
- Prints function calls, including arguments and return values
- Handles recursive calls

## Project Structure

- `/prf.c` – assignment solution implementation
- `/example.c` – reference/example skeleton
- `/tests_for_students` – test environment provided to students
  - `run_tests.sh` – test runner script
  - `tests/` – test inputs and expected outputs
- `/HW3.pdf` – assignment instructions

## Build and Run

Basic compilation:

```bash
gcc -std=c99 prf.c -o prf
```

Run example:

```bash
./prf <symbol_name> <num_params> <path_to_program> [program_args...]
```

## Run the Provided Tests

The `tests_for_students` directory includes a test script:

```bash
cd tests_for_students
chmod +x run_tests.sh
./run_tests.sh
```

> Note: the script expects `.c` files to be located in `tests_for_students/tests` during execution.
