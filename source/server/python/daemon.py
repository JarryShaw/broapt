# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import dataclasses
import multiprocessing
import os
import typing
import uuid

import flask

from process import process

# API info
@dataclasses.dataclass
class Info:
    name: str
    uuid: str
    mime: str

    report: str
    inited: bool
    locked: typing.Any

    workdir: str
    environ: typing.Mapping[str, str]
    install: typing.List[str]
    scripts: typing.List[str]


# main app
app = flask.Flask(__name__)

# help message
HELP_v1_0 = os.linesep.join((
    'BroAPT Daemon APIv1.0 Usage:',
    '',
    '- GET    /api/v1.0/list',
    '- GET    /api/v1.0/report/<id>',
    '- POST   /api/v1.0/scan data={"key": "value"}',
    '- DELETE /api/v1.0/delete/<id>',
))
__help__ = os.linesep.join((
    'BroAPT Daemon API Usage:',
    '',
    '# v1.0',
    '',
    '- GET    /api/v1.0/list',
    '- GET    /api/v1.0/report/<id>',
    '- POST   /api/v1.0/scan data={"key": "value"}',
    '- DELETE /api/v1.0/delete/<id>',
))

# worker pool
manager = multiprocessing.Manager()
RUNNING = manager.list()  # list[uuid.UUID]
SCANNED = manager.dict()  # dict[uuid.UUID, bool]
APILOCK = manager.dict()  # dict[shared, manager.Lock]
APIINIT = manager.dict()  # dict[shared, manager.Value]


@app.errorhandler(ValueError)
def invalid_id(error):
    return flask.jsonify(status=400,
                         error=str(error),
                         message='invalid ID format')


@app.errorhandler(400)
@app.errorhandler(KeyError)
def invalid_info(error):
    return flask.jsonify(status=400,
                         error=str(error),
                         message='invalid info format')


@app.errorhandler(404)
def id_not_found(error):
    return flask.jsonify(status=404,
                         error=str(error),
                         message='ID not found')


@app.route('/api', methods=['GET'])
def root():
    return __help__


@app.route('/api/v1.0', methods=['GET'])
def help_():
    return HELP_v1_0


@app.route('/api/v1.0/list', methods=['GET'])
def list_():
    info = list()
    info.extend(dict(id=uid, inited=None, scanned=True, reported=None, deleted=False) for uid in RUNNING)
    info.extend(dict(id=uid, inited=None, scanned=True, reported=flag, deleted=False) for (uid, flag) in SCANNED.items())  # pylint: disable=line-too-long
    return flask.jsonify(info)


@app.route('/api/v1.0/report', methods=['GET'])
def get_none():
    return 'ID Required: /api/v1.0/report/<id>'


@app.route('/api/v1.0/report/<id_>', methods=['GET'])
def get(id_):
    uid = uuid.UUID(id_)
    if uid in RUNNING:
        return flask.jsonify(id=uid, inited=None, scanned=False, reported=None, deleted=False)
    if uid in SCANNED:
        return flask.jsonify(id=uid, inited=None, scanned=True, reported=SCANNED[uid], deleted=False)
    return flask.abort(404)


@app.route('/api/v1.0/scan', methods=['POST'])
def scan():
    json = flask.request.get_json()
    if json is None:
        flask.abort(400)

    shared = json['shared']
    if shared not in APILOCK:
        APILOCK[shared] = manager.Lock()  # pylint: disable=no-member
        APIINIT[shared] = manager.Value('B', json['inited'])

    info = Info(
        name=json['name'],
        uuid=json['uuid'],
        mime=json['mime'],
        report=json['report'],
        inited=APIINIT[shared],
        locked=APILOCK[shared],
        workdir=json['workdir'],
        environ=json['environ'],
        install=json['install'],
        scripts=json['scripts'],
    )

    RUNNING.append(info.uuid)
    flag = process(info)

    with contextlib.suppress(ValueError):
        RUNNING.remove(info.uuid)
    SCANNED[info.uuid] = flag

    return flask.jsonify(id=info.uuid, inited=info.inited.value, scanned=True, reported=flag, deleted=False)


@app.route('/api/v1.0/delete', methods=['DELETE'])
def delete_none():
    return 'ID Required: /api/v1.0/delete/<id>'


@app.route('/api/v1.0/delete/<id_>', methods=['DELETE'])
def delete(id_):
    uid = uuid.UUID(id_)
    if uid in RUNNING:
        RUNNING.remove(uid)
        return flask.jsonify(id=uid, inited=None, scanned=False, reported=None, deleted=True)
    if uid in SCANNED:
        del SCANNED[uid]
        return flask.jsonify(id=uid, inited=None, scanned=True, reported=SCANNED[uid], deleted=True)
    return flask.jsonify(id=uid, inited=None, scanned=None, reported=None, deleted=True)
