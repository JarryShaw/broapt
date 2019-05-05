# BroAPT Core - Extraction Framework

This work is the extraction framework of BroAPT, which based on
[File Analysis](https://docs.zeek.org/en/stable/frameworks/file-analysis.html) framework of the
infamous [Zeek](zeek/zeek) Network Security Monitor, with a proper Python wrapper to fulfil the
indended design.

## Prerequisites

- Bro/Zeek, version 2.6.1
  > __NOTE__: on Ubuntu 16.04, no binary distribution of version 2.6.1 is available
  * for macOS, run `brew install bro`
  * for binary distribution, see [this page](https://www.zeek.org/download/packages.html)
  * some binary distributions can also be found in `/vendor/archive/` folder
  * if wish to build from source, a sample script can be found in `/docker/` folder
  * in `/vendor/Makefile`, you may also find how to build from source on macOS with a
    Pipenv virtual environment
- Python, version 3.5+ (tested only on 3.5.2 and 3.7.3)
  > __NOTE__: requirements are provided in `./vendor/python/` folder
  * [`python-magic`](https://github.com/ahupp/python-magic)

For Docker addict, a `Dockerfile` and a `docker-compose.yml` are both provided, just hit and go.
For development environment, `make` and `pipenv` are the two things playing around my workflow.

## Environment

- `BRO_MIME` -- Bro MIME while list
- `BRO_PROTOCOL` -- Bro protocol while list

- `BUF_SIZE` -- Bro file reassembly buffer size
- `SIZE_LIMIT` -- Bro extracted file size limit

- `CORE_CPU` -- concurrent process limit (*default*: 5)
- `CORE_INT` -- sleep interval (*default*: 10s)

- `DUMP_MIME` -- if store extracted files by MIME types (*default*: `true`)
- `DUMP_PATH` -- where extracted files will be stored (*default*: `/dump/`)
- `PCAP_PATH` -- path to PCAP source files (*default*: `/pcap/`)
- `LOGS_PATH` -- path to log files (*default*: `/var/log/bro/`)

- `MIME_UPDATE` -- force update `mime2ext` database (*default*: 0)

## Usage

### Extraction Framework

```shell
$ cd ./source/
$ python3 ./python/ [<path-to-pcap> ...]
```

This will extract files transferred in the network traffic, as stored in the PCAP sources.
The naming convention for the extracted files is: `${PROTOCOL}-${FILE_UID}.${FILE_EXT}`.

In default, all files are extracted to `${DUMP_PATH}` and saved with identification of its
MIME type.

- if `${DUMP_MIME}` sets to `true`, files will be classified in folders named after its MIME
  type, i.e. `${CONTENT_TYPE}/${SUBTYPE}/${PROTOCOL}-${FILE_UID}.${FILE_EXT}`
- otherwise, files will be named as `${PROTOCOL}-${FILE_UID}.${CONTENT_TYPE}.${SUBTYPE}.${FILE_EXT}`

For now, known supported protocols are: DTLS, FTP, HTTP, IRC and SMTP.

### Generation Utility

In `./source/python[-dev]/gen/` folder, two scripts are provided.

`fix-missing.py` is to read `${LOGS_PATH}/processed_mime.log`, which lists unexpected MIMEs missing
in Bro script `./source/scripts/file-extensions.bro`, and try to fix and update the missing
mappings.

`mime2ext.py` is to generate and update the mappings listed in Bro script
`./source/scripts/file-extensions.bro`.
