# BroAPT App - Detection Framework

This work is the detection framework of BroAPT, which is designed to be a flexible and customisable
APT detection framework. ML models and their corresponding APIs can be added to this work without
any specifications and declarations.

## Prerequisites

- Python, version 3.6+ (tested only on 3.6.8 & 3.7.3)
  - [`requests`](http://python-requests.org) -- for the default API, can be changed on demand

For Docker addict, a `Dockerfile` and a `docker-compose.yml` are both provided, just hit and go.
For development environment, `make` and `pipenv` are the two things playing around my workflow.

## Environment

- `APP_CPU` -- concurrent process limit (*default*: 10)
- `APP_INT` -- sleep interval (*default*: 10s)

- `DUMP_MIME` -- if store extracted files by MIME types (*default*: `true`)
- `DUMP_PATH` -- where extracted files will be stored (*default*: `/dump/`)
- `LOGS_PATH` -- path to log files (*default*: `/var/log/bro/`)
- `API_ROOT` -- root path to APIs (*default*: `/api/`)

> __NOTE__: the following environment variables are used only for the default API, and can be
>           removed if some other default API introduced

- `VT_API` -- VirusTotal API key
- `VT_LOG` -- path to store VirusTotal file scan reports & runtime logs
- `VT_INT` -- VirusTotal sleep interval (*default*: 10s)
- `VT_RETRY` -- maximum times of retry for retrieving VirusTotal file scan reports (*default*: 3)

## Usage

```shell
$ cd ./source/
$ python3 ./python/
```

This will run API scripts on extracted files. The mechanism of choosing API scripts is:

- fetch an extracted file, say its path is `${FILE_PATH}` and name is `${FILE_NAME}`
- obtain the MIME type of the extracted file, say `${FILE_MIME}`
- if `./source/python[-dev]/api/${FILE_MIME}${API_SUFFIX}` exists (say `${MIME_API}`)
  - note that `${MIME_API}` can either be a file or a directory
  - the API should take three command line arguments as specified below
- else use the default API, i.e. `./source/python[-dev]/api/${DEFAULT_API}`
- run `python3 ${MIME_API} ${FILE_PATH} ${FILE_NAME} ${FILE_MIME}`
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
- `ratio` -- `float`, a `positive/total` ratio
