# -*- coding: utf-8 -*-

import argparse

import dotenv


def parse_env():
    parser = argparse.ArgumentParser(prog='broaptd',
                                     description='BroAPT Daemon')
    parser.add_argument('-v', '--version', action='version', version='1.0')
    parser.add_argument('-e', '--env', help='path to dotenv file')

    server_parser = parser.add_argument_group(title='server arguments')
    server_parser.add_argument('-t', '--host', help='the hostname to listen on')
    server_parser.add_argument('-p', '--port', help='the port of the webserver')

    compose_parser = parser.add_argument_group(title='compose arguments')
    compose_parser.add_argument('-c', '--docker-compose', help="path to BroAPT's docker-compose.yml")
    compose_parser.add_argument('-d', '--dump-path', help='path to extracted files')
    compose_parser.add_argument('-l', '--logs-path', help='path to log files')

    api_parser = parser.add_argument_group(title='API arguments')
    api_parser.add_argument('-r', '--api-root', help='path to detection APIs')
    api_parser.add_argument('-a', '--api-logs', help='path to API runtime logs')

    runtime_parser = parser.add_argument_group(title='runtime arguments')
    runtime_parser.add_argument('-i', '--interval', help='sleep interval')
    runtime_parser.add_argument('-m', '--max-retry', help='command retry')

    # parse dotenv location
    args = parser.parse_args()
    path = args.env

    # load dotenv
    if path is not None:
        return dotenv.dotenv_values(dotenv_path=path)
    return dict()


def parse_args():
    # parse dotenv
    env = parse_env()

    # get default values
    host = env.get('BROAPT_SERVER_HOST', '0.0.0.0')
    port = env.get('BROAPT_SERVER_PORT', '5000')
    docker_compose = env.get('BROAPT_DOCKER_COMPOSE', 'docker-compose.yml')
    dump_path = env.get('BROAPT_DUMP_PATH')
    logs_path = env.get('BROAPT_LOGS_PATH')
    api_root = env.get('BROAPT_API_ROOT')
    api_logs = env.get('BROAPT_API_LOGS')
    interval = env.get('BROAPT_INTERVAL', '10')
    max_retry = env.get('BROAPT_MAX_RETRY', '3')

    # prepare parser
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-e', '--env')
    parser.add_argument('-t', '--host', default=host)
    parser.add_argument('-p', '--port', default=port, type=int)
    parser.add_argument('-c', '--docker-compose', default=docker_compose)
    parser.add_argument('-d', '--dump-path', default=dump_path, required=(dump_path is None))
    parser.add_argument('-l', '--logs-path', default=logs_path, required=(logs_path is None))
    parser.add_argument('-r', '--api-root', default=api_root, required=(api_root is None))
    parser.add_argument('-a', '--api-logs', default=api_logs, required=(api_logs is None))
    parser.add_argument('-i', '--interval', default=interval, type=int)
    parser.add_argument('-m', '--max-retry', default=max_retry, type=int)

    # parse arguments
    return parser.parse_args()
