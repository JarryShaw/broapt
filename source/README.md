# Broapt

### Source files

- [`Makefile`](source/Makefile)
  - `make init` -- create useful directories
  - `make clean` -- cleanup ignored files
- [`docs`](source/docs) -- useful documentations
  - [`docs/reass.txt`](source/docs/reass.txt) -- TCP reassembly algorithm
  - [`docs/rfc791.txt`](source/docs/rfc791.txt) -- RFC 791, Internet Protocol
  - [`docs/rfc815.txt`](source/docs/rfc815.txt) -- RFC 815, IP Datagram Reassembly Algorithm
- [`python`](source/python) -- Python source files
  - `python/__main__.py` -- module entry; test file for extracting files from reassembled application layer data
- [`scripts`](source/scripts) -- Bro policy scripts
  - [`scripts/__load__.bro`](source/scripts/__load__.bro) -- module entry
  - [`scripts/config.bro`](source/scripts/config.bro) -- configuration
  - [`scripts/main.bro`](source/scripts/main.bro) -- main implementation; reassemble TCP datagram in pure Bro script (__DEBUG__)
  - [`scripts/logging.bro`](source/scripts/logging.bro) -- logging implementation (__TESTING__)
  - [`scripts/contents.bro`](source/scripts/contents.bro) -- store reassembled application layer data on demand (__DEPRECATED__)
  - [`scripts/plugins`](source/scripts/plugins) -- Bro plugins
    - [`scripts/plugins/__load__.bro`](source/scripts/plugins/__load__.bro) -- module entry
    - [`scripts/plugins/buffer.bro](source/scripts/plugins/buffer.bro) -- `buffer` for TCP reassembly (from PyPCAPKit, c.f. `pcapkit.reassembly.tcp.TCP_Reassembly._buffer`)
    - [`scripts/plugins/bytearray.bro`](source/scripts/plugins/bytearray.bro) -- `bytearray` for TCP reassembly (from Python, c.f. `builtins.bytearray`)

### Ignored files

- `contents` -- directory for reassembled application layer data; name after `id.orig_h:id.orig_p-id.resp_h:id.resp_p_[orig|resp]_[count].dat`
- `extract_files` -- directory for extracted files from reassembled application layer data
- `*.log` -- Bro generated logs
- `logs` -- directory for logs
