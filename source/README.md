# Broapt

### Source files

- `Makefile`
  - `make init` -- create useful directories
  - `make clean` -- cleanup ignored files
  - `make test` -- make test directory in `/test/$(DIR)` (`random` in default)
- `custom` -- C/C++ implementations
  - `reass.cc` -- C++ 11 based TCP reassembly implementation (works with `scripts/writer.bro`)
- `docs` -- useful documentations
  - `docs/reass.txt` -- TCP reassembly algorithm
  - `docs/rfc791.txt` -- RFC 791, Internet Protocol
  - `docs/rfc815.txt` -- RFC 815, IP Datagram Reassembly Algorithm
- `python` -- Python source files
  - `python/__main__.py` -- module entry; test file for extracting files from reassembled application layer data
- `scripts` -- Bro policy scripts
  - `scripts/__load__.bro` -- module entry
  - `scripts/config.bro` -- configuration
  - `scripts/contents.bro` -- store reassembled application layer data on demand (__DEPRECATED__)
  - `scripts/logging.bro` -- logging implementation (__DEPRECATED__)
  - `scripts/main.bro` -- main implementation; reassemble TCP datagram in pure Bro script (__DEPRECATED__)
  - `scripts/reass.bro` -- final implementation (__STALE__)
  - `scripts/telepathy.bro` -- Broker sample code
  - `scripts/writer.bro` -- another logging implementation (__TESTING__)
  - `scripts/custom` -- customised helper scripts
  - `scripts/helpers` -- Bro helper scripts
    - `scripts/helpers/__load__.bro` -- module entry
    - `scripts/helpers/buffer.bro` -- `buffer` for TCP reassembly (from PyPCAPKit, c.f. `pcapkit.reassembly.tcp.TCP_Reassembly._buffer`)
    - `scripts/helpers/bytearray.bro` -- `bytearray` for TCP reassembly (from Python, c.f. `builtins.bytearray`)
    - `scripts/helpers/packet.bro` -- `packet` for TCP reassembly (from PyPCAPKit, c.f. `pcapkit.reassembly.tcp.TCP_Reassembly.datagram[...]`)
  - `scripts/plugins` -- Bro hook plugins

### Ignored files

- `contents` -- directory for reassembled application layer data; name after `[uid]_id.orig_h:id.orig_p-id.resp_h:id.resp_p_[orig|resp]_[ack].dat`
- `extract_files` -- directory for extracted files from reassembled application layer data
- `*.log` -- Bro generated logs
- `logs` -- directory for logs

### Mode Comparison

> test file: 1601 packets, ~1.4MB

- verbose mode (see `scripts/reass.bro`, set `verbose_mode = T`)
  - real    0m4.759s
  - user    0m2.031s
  - sys     0m1.969s
- all protocols (see `scripts/reass.bro`)
  - real    0m3.451s
  - user    0m1.883s
  - sys     0m0.950s
- HTTP only (see `scripts/plugins/http.bro`)
  - real    0m2.991s
  - user    0m1.924s
  - sys     0m0.786s

### Implementation Comparison (__OUTDATED__)

> test file: 1601 packets, ~1.4MB
>
> Bro processing of the test file:
>   * real    0m1.099s
>   * user    0m0.783s
>   * sys     0m0.225s

- Pure Bro Implementation (see `scripts/main.bro`)
  - real    14m36.081s
  - user    13m57.274s
  - sys	    0m28.832s
- Hybrid Implementation with Python (see `scripts/writer.bro` and `python/reader.py`)
  - real    0m20.440s
  - user    0m18.258s
  - sys	    0m2.018s
- Pure Python Implementation (based on PyPCAPKit with DPKT engine)
  - real    0m18.693s
  - user    0m16.850s
  - sys	    0m1.211s
- Hybrid Implementation with C/C++ (see `scripts/writer.bro` and `custom/reass.cc`)
  - real    0m2.352s
  - user    0m1.243s
  - sys     0m0.481s
