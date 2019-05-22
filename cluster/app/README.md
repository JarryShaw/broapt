# BroAPT App - Detection Framework

This work is the detection framework of BroAPT, which is designed to be a flexible and customisable
APT detection framework. ML models and their corresponding APIs can be added to this work without
any specifications and declarations.

## Prerequisites

- Python, version 3.6+ (tested only on 3.6.8 & 3.7.3)
  - [`dataclasses`](https://github.com/ericvsmith/dataclasses)
  - [`PyYAML`](https://github.com/yaml/pyyaml) -- with optional `libyaml`

For Docker addict, a `Dockerfile` and a `docker-compose.yml` are both provided, just hit and go.
For development environment, `make` and `pipenv` are the two things playing around my workflow.

## Environment

- `SERVER_NAME_HOST` -- daemon server port (*default*: `localhost`)
- `SERVER_NAME_PORT` -- daemon server port (*default*: 5000)

- `BROAPT_APP_CPU` -- concurrent process limit (*default*: 10)
- `BROAPT_APP_INTERVAL` -- sleep interval (*default*: 10s)
- `BROAPT_MAX_RETRY` -- maximum times of retry for running commands (*default*: 3)

- `BROAPT_API_ROOT` -- root path to APIs (*default*: `/api/`)
- `BROAPT_API_LOGS` -- path to API runtime logs (*default*: `/var/log/bro/api/`)

- `BROAPT_DUMP_PATH` -- where extracted files will be stored (*default*: `FileExtract::prefix`)
- `BROAPT_LOGS_PATH` -- path to log files (*default*: `/var/log/bro/`)

> __NOTE__: the following environment variables are used only for the default API, and can be
>           removed if some other default API introduced

- `VT_API` -- VirusTotal API key
- `VT_LOG` -- path to store VirusTotal file scan reports & runtime logs (`/var/log/bro/tmp/`)
- `VT_INT` -- VirusTotal sleep interval (*default*: 60s)
- `VT_RETRY` -- maximum times of retry for retrieving VirusTotal file scan reports (*default*: 3)
- `VT_PERCENT` -- percentage of positive threshold (*default*: 50%)

## Usage

```shell
$ cd ./source/
$ python3 ./python/
```

This will run API scripts on extracted files. The mechanism of choosing API scripts is:

- fetch an extracted file, then obtain MIME type of the file, say `${FILE_MIME}`
- if `${API_ROOT}/${FILE_MIME}` exists (say `${API_PATH}`)
  - note that `${API_PATH}` can either be a file or a directory
  - the API should be configured in the YAML file `${API_ROOT}/api.yml`
- else use the default API, as specified in the config file
- if first time, run installation scripts specified in the config file
- run detection scripts specified in the config file
- then add a new line of report to `${LOGS_PATH}/processed_rate.log`

### API Specification

The API should be configured through `${API_ROOT}/api.yml`.

See the sample file `vendor/api/api.yml` for more information.

### Log Specification

The final report should be always stored at `${LOGS_PATH}/processed_rate.log`. It
should be a **one-line** JSON string, with following fields:

- `time` -- `float`, timestamp when the report is generated
- `path` -- `str`, path to the extracted file
- `name` -- `str`, name of the extracted file
- `mime` -- `str`, MIME type of the extracted file
- `rate` -- `bool`, malicious or not
