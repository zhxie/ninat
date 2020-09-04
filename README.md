# ninat

**ninat** is a tool dealing with NAT traversal using Nintendo service.

## Usage

```
ninat

# Use SOCKS proxy
ninat -s <ADDRESS>
```

### Flags

`-h, --help`: Prints help information.

`-V, --version`: Prints version information.

### Options

`-s, --socks-proxy <ADDRESS>`: SOCKS proxy. Only support SOCKS5 proxy.

`--username <VALUE>`: Username. This value should be set only when the SOCKS5 server requires the username/password authentication.

`--password <VALUE>`: Password. This value should be set only when the SOCKS5 server requires the username/password authentication.

`-w, --timeout <VALUE>`: Timeout to wait for each response, `0` as no timeout, default as `3000` ms.

## License

ninat is licensed under [the MIT License](/LICENSE).
