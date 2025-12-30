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

## Tetragon Integration

Cyrenus integrates with Tetragon for runtime security monitoring and anti-RCE protection.

### Install Tetragon

```bash
sudo ./scripts/install_tetragon.sh
sudo cp config/tetragon/policies/*.yaml /etc/tetragon/policies/
sudo systemctl start tetragon
sudo systemctl enable tetragon
```

### Features

- **Anti-RCE Protection**: Detects and blocks remote code execution attempts
- **Process Monitoring**: Tracks suspicious process behavior
- **File Integrity Monitoring**: Monitors access to sensitive files
- **Attack Correlation**: Links network and application-layer attacks

See [docs/tetragon-integration.md](docs/tetragon-integration.md) for detailed documentation.

## License

[Your chosen license]

