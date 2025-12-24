# Cyrenus

Cyrenus is an eBPF-based network traffic monitoring and management tool.

## Prerequisites

- Linux kernel 5.8 or later
- LLVM and Clang 10 or later
- libelf-dev
- libbpf-dev
- libmicrohttpd-dev
- libconfig-dev
- libjson-c-dev

On Ubuntu or Debian, you can install these dependencies with:

```
sudo apt-get install llvm clang libelf-dev libbpf-dev libmicrohttpd-dev libconfig-dev libjson-c-dev
```

## Building

To build the project, simply run:

```
make
```

This will compile both the main program and the eBPF program.

## Running

Before running, make sure to update the `config/cyrenus.conf` file with your desired settings.

To run the program:

```
sudo ./cyrenus config/cyrenus.conf
```

Note: Root privileges are required to load the eBPF program.

## Stopping

To stop the program, press Ctrl+C.

## License

[Your chosen license]

