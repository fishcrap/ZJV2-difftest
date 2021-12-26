# ZJV2-difftest

ZJV2's difftest framework based on Verilator, QEMU and GDB.


## Requirement

- riscv-gnu-toolchain
- qemu-system-riscv64
- verilator

**NOTICE**: if you need a dockerized environment with all above tools, check [zjv2-env](https://github.com/riscv-zju/zjv2-env)

## Usage

`ZJV2-difftest` has been imported as a Git submodule of `ZJV2`. All the stuff regarding difftest can be fetched from `ZJV2` repo.

The following is a simple use case:

```bash
$ cd ZJV2-difftest
$ make prepare ELF=riscv-tests/rv64um-p-div
$ make
$ cd build && ./emulator -elf
```


## Documents

- [编译 RISC-V 版本的 rt-thread](doc/rt-thread.md)
- [RISC-V GDB 中读取 CSR](doc/gdb-csr.md)
