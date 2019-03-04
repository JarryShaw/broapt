# Broapt

### Source files

- [`Makefile`](source/Makefile)
  - `make init` -- create useful directories
  - `make clean` -- cleanup ignored files
- [`python`](source/python) -- Python source files
  - `python/__main__.py` -- module entry; test file for extracting files from reassembled application layer data
- [`scripts`](source/scripts) -- Bro policy scripts
  - [`scripts/__load__.bro`](source/scripts/__load__.bro) -- module entry
  - [`scripts/config.bro`](source/scripts/config.bro) -- configuration
  - [`scripts/main.bro`](source/scripts/main.bro) -- main implementation; store reassembled application layer data on demand

### Ignored files

- `contents` -- directory for reassembled application layer data; name after `id.orig_h:id.orig_p-id.resp_h:id.resp_p_[orig|resp]_[count].dat`
- `extract_files` -- directory for extracted files from reassembled application layer data
- `*.log` -- Bro generated logs
