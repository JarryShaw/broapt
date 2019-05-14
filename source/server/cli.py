# -*- coding: utf-8 -*-

import argparse


def get_parser():
    parser = argparse.ArgumentParser(prog='broapt-appd',
                                     description='BroAPT-App Daemon')
    parser.add_argument('-v', '--version', action='version', version='1.0')

    server_parser = parser.add_argument_group(title='server arguments')
    server_parser.add_argument('-t', '--host', default='0.0.0.0',
                               help='the hostname to listen on')
    server_parser.add_argument('-p', '--port', default='5000', type=int,
                               help='the port of the webserver')

    compose_parser = parser.add_argument_group(title='compose arguments')
    compose_parser.add_argument('-c', '--docker-compose', required=True,
                                help='path to BroAPT-App docker-compose.yml')
    compose_parser.add_argument('-d', '--dump-path', required=True,
                                help='path to extracted files')
    compose_parser.add_argument('-l', '--logs-path', required=True,
                                help='path to log files')

    api_parser = parser.add_argument_group(title='API arguments')
    api_parser.add_argument('-r', '--api-root', required=True,
                            help='path to detection APIs')
    api_parser.add_argument('-a', '--api-logs', required=True,
                            help='path to API runtime logs')

    runtime_parser = parser.add_argument_group(title='runtime arguments')
    runtime_parser.add_argument('-i', '--interval', type=int, default=10,
                                help='sleep interval')
    runtime_parser.add_argument('-m', '--max-retry', type=int, default=3,
                                help='command retry')

    return parser
