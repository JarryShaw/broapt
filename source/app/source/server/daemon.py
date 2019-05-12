# -*- coding: utf-8 -*-

import dataclasses
import multiprocessing
import typing
import uuid

import flask

from .process import process

# API info
@dataclasses.dataclass
class Info:
    uuid: str
    mime: str
    report: str

    _inited: bool
    workdir: str
    environ: typing.Mapping[str, str]
    install: typing.List[str]
    scanner: typing.List[str]


# main app
app = flask.Flask(__name__)

# help message
HELP_v1_0 = '''\
- GET    /api/v1.0/list
- GET    /api/v1.0/report/<id>
- POST   /api/v1.0/scan data={"key": "value"}
- DELETE /api/v1.0/delete/<id>
'''
__help__ = f'''\
BroAPT-App Daemon API Usage:

# v1.0

{HELP_v1_0}
'''

# worker pool
manager = multiprocessing.Manager()
RUNNING = manager.list()  # list[uuid.UUID]
SCANNED = manager.dict()  # dict[uuid.UUID, bool]


@app.errorhandler(ValueError)
def invalid_id(error):
    return flask.jsonify(status=400,
                         error=error,
                         message='invalid ID format')


@app.errorhandler(400)
@app.errorhandler(KeyError)
def invalid_info(error):
    return flask.jsonify(status=400,
                         error=error,
                         message='invalid info format')


@app.errorhandler(404)
def id_not_found(error):
    return flask.jsonify(status=404,
                         error=error,
                         message='ID not found')


@app.route('/api', methods=['GET'])
def root():
    return __help__


@app.route('/api/v1.0', methods=['GET'])
def help_():
    return HELP_v1_0


@app.route('/api/v1.0/list', methods=['GET'])
def list_():
    return flask.jsonify(running=RUNNING,
                         scanned=SCANNED)


@app.route('/api/v1.0/report', methods=['GET'])
def get_none():
    return 'ID Required: /api/v1.0/report/<id>'


@app.route('/api/v1.0/report/<str:id_>', methods=['GET'])
def get(id_):
    uid = uuid.UUID(id_)
    if uid in RUNNING:
        return flask.jsonify(id=uid, scanned=False, report=None)
    if uid in SCANNED:
        return flask.jsonify(id=uid, scanned=True, report=SCANNED[uid])
    return flask.abort(404)


@app.route('/api/v1.0/scan', methods=['POST'])
def scan():
    if not flask.request.json:
        flask.abort(400)
    json = flask.request.json
    info = Info(uuid=json['uuid'],
                mime=json['mime'],
                report=json['report'],
                _inited=json['_inited'],
                workdir=json['workdir'],
                environ=json['environ'],
                install=json['install'],
                scanner=json['scanner'])
    if process(info):
        return flask.jsonify()
    return flask.jsonify()


@app.route('/api/v1.0/delete', methods=['DELETE'])
def delete():
    pass
