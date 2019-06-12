# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import abc
import binascii
import contextlib
import ctypes
import dataclasses
import datetime
import enum
import functools
import ipaddress
import json
import multiprocessing
import os
import textwrap
import time
import typing
import warnings

from const import LOGS_PATH

__all__ = [
    # Bro types
    'bro_addr', 'bro_bool', 'bro_count', 'bro_double', 'bro_enum', 'bro_int',
    'bro_interval', 'bro_list', 'bro_port', 'bro_set', 'bro_string',
    'bro_subnet', 'bro_time',

    # logging fields
    'AddrField', 'BoolField', 'CountField', 'DoubleField', 'EnumField',
    'IntField', 'IntervalField', 'PortField', 'StringField', 'SubnetField',
    'TimeField',

    # logging model
    'Model',

    # logging writers
    'Logger', 'JSONLogger', 'TEXTLogger',
]

###############################################################################
# warnings & exceptions


class LogWarning(Warning):
    pass


class IntWarning(LogWarning):
    pass


class CountWarning(LogWarning):
    pass


class BoolWarning(LogWarning):
    pass


class FieldError(TypeError):
    pass


class ModelError(ValueError):
    pass


###############################################################################
# Bro logging fields


def _type_check(func):
    @functools.wraps(func)
    def check(self, value):
        if self.predicate(value):
            return func(self, self.cast(value))
        raise FieldError(f'{self.type()} is required (got type {type(value).__name__!r})')
    return check


class _Field(metaclass=abc.ABCMeta):  # pylint: disable=abstract-method

    ###########################################################################
    # APIs for overload

    @staticmethod
    @abc.abstractmethod
    def type():
        pass

    @staticmethod
    def jsonify(value):
        return json.dumps(value)

    @staticmethod
    def textify(value):
        return str(value)

    @staticmethod
    def predicate(value):  # pylint: disable=unused-argument
        return True

    @staticmethod
    def cast(value):
        return value

    ###########################################################################

    @property
    def context(self):
        return self.__str__()

    @classmethod
    def logging(cls, value, *, use_json=False):
        if use_json:
            return cls._to_json(cls, value)
        return cls._to_text(cls, value)

    def __init__(self, value, *, use_json=False):
        self._json = use_json
        self._value = value

    def __str__(self):
        if self._json:
            return self._to_json(self._value)
        return self._to_text(self._value)

    def __repr__(self):
        return f'<{self.type()} {self}>'

    @_type_check
    def _to_json(self, value):
        return self.jsonify(value)

    @_type_check
    def _to_text(self, value):
        return self.textify(value)


class StringField(_Field):

    @staticmethod
    def type():
        return 'string'

    @staticmethod
    def cast(value):
        return str(value).encode('unicode-escape').decode()


class PortField(_Field):

    @staticmethod
    def type():
        return 'port'

    @staticmethod
    def predicate(value):
        if isinstance(value, int):
            if 0 <= value <= 65535:
                return True
            return False
        if isinstance(value, ctypes.c_uint16):
            return True
        return False

    @staticmethod
    def cast(value):
        if isinstance(value, int):
            return ctypes.c_uint16(value).value
        return value.value


class EnumField(_Field):

    @staticmethod
    def type():
        return 'enum'

    @staticmethod
    def predicate(value):
        return isinstance(value, enum.Enum)

    @staticmethod
    def cast(value):
        if isinstance(value, enum.Enum):
            return value.name
        return value


class IntervalField(_Field):

    @staticmethod
    def type():
        return 'interval'

    @staticmethod
    def predicate(value):
        if isinstance(value, datetime.timedelta):
            return True
        try:
            float(value)
        except (TypeError, ValueError):
            return False
        return True

    @staticmethod
    def cast(value):
        if isinstance(value, datetime.timedelta):
            return '%.6f' % value.total_seconds()
        return '%.6f' % float(value)

    @staticmethod
    def jsonify(value):
        return '%s%s' % (value[-5], value[-5:].strip('0'))

    @staticmethod
    def textify(value):
        return '%s%s' % (value[-5], value[-5:].strip('0'))


class AddrField(_Field):

    @staticmethod
    def type():
        return 'addr'

    @staticmethod
    def predicate(value):
        try:
            ipaddress.ip_address(value)
        except (TypeError, ValueError):
            return False
        return True

    @staticmethod
    def cast(value):
        return str(ipaddress.ip_address(value))


class SubnetField(_Field):

    @staticmethod
    def type():
        return 'subnet'

    @staticmethod
    def predicate(value):
        try:
            ipaddress.ip_network(value)
        except (TypeError, ValueError):
            return False
        return True

    @staticmethod
    def cast(value):
        return str(ipaddress.ip_network(value))


class IntField(_Field):

    @staticmethod
    def type():
        return 'int'

    @staticmethod
    def predicate(value):
        if isinstance(value, int):
            if int.bit_length(value) > 64:
                warnings.warn(f'{value} exceeds maximum value', IntWarning)
            return True
        if isinstance(value, ctypes.c_int64):
            return True
        return False

    @staticmethod
    def cast(value):
        if isinstance(value, int):
            return ctypes.c_int64(value).value
        return value.value


class CountField(_Field):

    @staticmethod
    def type():
        return 'count'

    @staticmethod
    def predicate(value):
        if isinstance(value, int):
            if int.bit_length(value) > 64:
                warnings.warn(f'{value} exceeds maximum value', CountWarning)
            if value < 0:
                warnings.warn(f'negative value {value} casts to unsigned', CountWarning)
            return True
        if isinstance(value, ctypes.c_uint64):
            return True
        return False

    @staticmethod
    def cast(value):
        if isinstance(value, int):
            return ctypes.c_uint64(value).value
        return value.value


class TimeField(_Field):

    @staticmethod
    def type():
        return 'time'

    @staticmethod
    def predicate(value):
        if isinstance(value, datetime.datetime):
            return True
        if isinstance(value, time.struct_time):
            return True
        try:
            float(value)
        except (TypeError, ValueError):
            return False
        return True

    @staticmethod
    def cast(value):
        if isinstance(value, datetime.datetime):
            return value.timestamp()
        if isinstance(value, time.struct_time):
            return time.mktime(value)
        return float(value)


class DoubleField(_Field):

    @staticmethod
    def type():
        return 'double'

    @staticmethod
    def predicate(value):
        try:
            float(value)
        except (TypeError, ValueError):
            return False
        return True

    @staticmethod
    def cast(value):
        return '%.6f' % float(value)

    @staticmethod
    def jsonify(value):
        return '%s%s' % (value[-5], value[-5:].strip('0'))

    @staticmethod
    def textify(value):
        return '%s%s' % (value[-5], value[-5:].strip('0'))


class BoolField(_Field):

    @staticmethod
    def type():
        return 'bool'

    @staticmethod
    def predicate(value):
        if not isinstance(value, bool):
            warnings.warn(f'cast {type(value).__name__!r} type to bool value', BoolWarning)
        return True

    @staticmethod
    def jsonify(value):
        return 'true' if bool(value) else 'false'

    @staticmethod
    def textify(value):
        return 'T' if bool(value) else 'F'


###############################################################################
# Bro logging types

# basic Bro types
bro_string = typing.NewType('bro_string', StringField)
bro_port = typing.NewType('bro_port', PortField)
bro_enum = typing.NewType('bro_enum', EnumField)
bro_interval = typing.NewType('bro_interval', IntervalField)
bro_addr = typing.NewType('bro_addr', AddrField)
bro_subnet = typing.NewType('bro_subnet', SubnetField)
bro_int = typing.NewType('bro_int', IntField)
bro_count = typing.NewType('bro_count', CountField)
bro_time = typing.NewType('bro_time', TimeField)
bro_double = typing.NewType('bro_double', DoubleField)
bro_bool = typing.NewType('bro_bool', BoolField)

# generic Bro types
_bro_type = typing.TypeVar('bro_type', bro_string, bro_port, bro_enum, bro_interval,
                           bro_addr, bro_subnet, bro_int, bro_count, bro_time,
                           bro_double, bro_bool)


class _bro_list(typing.Generic[_bro_type]):
    pass


class _bro_set(typing.Generic[_bro_type]):
    pass


# container Bro types
bro_list = _bro_list
bro_set = _bro_set

###############################################################################
# Bro logging data model


class Model(metaclass=abc.ABCMeta):

    ###########################################################################
    # APIs for overload

    def default(self, field_typing):  # pylint: disable=unused-argument, no-self-use
        return False

    def fallback(self, field_typing):  # pylint: disable=no-self-use
        raise ModelError(f'unknown field type: {field_typing.__name__}')

    @property
    def json(self):
        return False

    ###########################################################################

    @property
    def dataclass_args(self):
        return dict(init=self.dataclass_init(),
                    repr=self.dataclass_repr(),
                    eq=self.dataclass_eq(),
                    order=self.dataclass_order(),
                    unsafe_hash=self.dataclass_unsafe_hash(),
                    frozen=False)

    @staticmethod
    def dataclass_init():
        return True

    @staticmethod
    def dataclass_repr():
        return True

    @staticmethod
    def dataclass_eq():
        return True

    @staticmethod
    def dataclass_order():
        return False

    @staticmethod
    def dataclass_unsafe_hash():
        return False

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        if dataclasses.is_dataclass(cls):
            cls = dataclasses.make_dataclass(cls.__name__,  # pylint: disable=self-cls-assignment
                                             [(field.name, field.type, field) for field in dataclasses.fields(cls)],
                                             bases=cls.mro(),
                                             namespace=cls.__dict__,
                                             init=cls.dataclass_init(),
                                             repr=cls.dataclass_repr(),
                                             eq=cls.dataclass_eq(),
                                             order=cls.dataclass_order(),
                                             unsafe_hash=cls.dataclass_unsafe_hash(),
                                             frozen=False)
        else:
            cls = dataclasses._process_class(cls,  # pylint: disable=protected-access, self-cls-assignment
                                             init=cls.dataclass_init(),
                                             repr=cls.dataclass_repr(),
                                             eq=cls.dataclass_eq(),
                                             order=cls.dataclass_order(),
                                             unsafe_hash=cls.dataclass_unsafe_hash(),
                                             frozen=False)
        return super().__new__(cls)

    def __post_init__(self):
        try:
            orig_exists = True
            try:
                orig = getattr(self, '__foo')
            except AttributeError:
                orig_exists = False
            setattr(self, '__foo', 1)
        except dataclasses.FrozenInstanceError as error:
            raise ModelError(f'invalid model: {error}').with_traceback(error.__traceback__) from None
        if orig_exists:
            setattr(self, '__foo', orig)
        else:
            delattr(self, '__foo')

        for field in dataclasses.fields(self):
            self._typing_check(field.type)
            value = getattr(self, field.name)
            factory = self._get_factory(field.type)
            setattr(self, field.name, factory(value))

    def _typing_check(self, field_typing):  # pylint: disable=inconsistent-return-statements
        if self.default(field_typing):
            return
        if field_typing in (bro_list, bro_set):
            raise FieldError(f'container Bro type not initialised')
        if hasattr(field_typing, '__supertype__'):
            if field_typing in _bro_type.__constraints__:  # pylint: disable=no-member
                return
            raise FieldError(f'unknown Bro type: {field_typing.__name__}')
        if hasattr(field_typing, '__origin__'):
            if field_typing.__origin__ not in (bro_list, bro_set):
                raise FieldError(f'unknown Bro type: {field_typing.__name__}')
            __args__ = field_typing.__args__
            if len(__args__) < 1:  # pylint: disable=len-as-condition
                raise FieldError('too few types for Bro container type')
            if len(__args__) > 1:
                raise FieldError('too many types for Bro container type')
            return self._typing_check(__args__[0])
        raise FieldError(f'unknown Bro type: {field_typing.__name__}')

    def _get_factory(self, field_typing):
        if hasattr(field_typing, '__supertype__'):
            supertype = field_typing.__supertype__
            return lambda value: supertype(value, use_json=self.json)
        if hasattr(field_typing, '__origin__'):
            if field_typing.__origin__ is bro_set:
                factory = self._get_factory(field_typing.__args__[0])
                return lambda iterable: set(factory(element, use_json=self.json) for element in iterable)
            if field_typing.__origin__ is bro_list:
                factory = self._get_factory(field_typing.__args__[0])
                return lambda iterable: list(factory(element, use_json=self.json) for element in iterable)
        return self.fallback(field_typing)


###############################################################################
# Bro logging writers


class Logger(metaclass=abc.ABCMeta):

    ###########################################################################
    # APIs for overload

    @property
    @abc.abstractmethod
    def format(self):
        pass

    @property
    def json(self):
        return False

    def open(self):
        with open(self._file, 'w'):
            pass

    def close(self):
        pass

    @abc.abstractmethod
    def log(self, model):
        pass

    def fallback(self, field_typing):  # pylint: disable=no-self-use
        raise ModelError(f'unknown field type: {field_typing.__name__}')

    def __pre_init__(self, path, model, *, log_suffix=None, async_write=True, **kwargs):
        pass

    ###########################################################################

    @property
    def path(self):
        return self._path

    def __init__(self, path, model, *, log_suffix=None, async_write=True, **kwargs):  # pylint: disable=unused-argument
        if not issubclass(model, Model):
            raise ModelError(f'type {model.__name__!r} is not a valid model')
        self.__pre_init__(path, model, log_suffix=log_suffix, async_write=async_write, **kwargs)

        if log_suffix is None:
            log_suffix = os.getenv('BROAPT_LOG_SUFFIX', '.log')

        self._model = model
        self._fields = self._init_fields(model)

        self._path = path
        self._file = os.path.join(LOGS_PATH, f'{path}{log_suffix}')

        parents = os.path.split(self._file)[0]
        os.makedirs(parents, exist_ok=True)

        if async_write:
            self._lock = multiprocessing.Lock()
        else:
            self._lock = contextlib.nullcontext()
        self.open()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _get_name(self, field_typing):
        if hasattr(field_typing, '__supertype__'):
            return field_typing.__supertype__.type()
        if hasattr(field_typing, '__origin__'):
            if field_typing.__origin__ is bro_set:
                return f'set[{self._get_name(field_typing.__args__[0])}]'
            if field_typing.__origin__ is bro_list:
                return f'vector[{self._get_name(field_typing.__args__[0])}]'
        return self.fallback(field_typing)

    def _init_fields(self, model):
        fields = dict()
        for field in dataclasses.fields(model):
            fields[field.name] = self._get_name(field.type)
        return fields

    def _init_model(self, *args, **kwargs):
        if args and isinstance(args[0], self._model):
            dataclass = args[0]
        else:
            dataclass = self._model(*args, **kwargs)
        return dataclass

    def write(self, *args, **kwargs):
        try:
            model = self._init_model(*args, **kwargs)
        except FieldError:
            raise
        except Exception as error:
            raise ModelError(f'invalid model: {error}').with_traceback(error.__traceback__) from None

        context = self.log(model)
        with self._lock:
            with open(self._file, 'a') as file:
                print(context, file=file)


class JSONLogger(Logger):

    @property
    def format(self):
        return 'json'

    @property
    def json(self):
        return True

    def log(self, model):
        return json.dumps(model, default=str)


class TEXTLogger(Logger):

    @property
    def format(self):
        return 'text'

    @property
    def seperator(self):
        return self._seperator

    @property
    def set_seperator(self):
        return self._set_seperator

    @property
    def empty_field(self):
        return self._empty_field

    @property
    def unset_field(self):
        return self._unset_field

    def __pre_init__(self, path, model, *, log_suffix=None, async_write=True,  # pylint: disable=unused-argument, arguments-differ
                     seperator='\x09', set_seperator=',', empty_field='(empty)', unset_field='-'):
        self._seperator = seperator
        self._set_seperator = set_seperator
        self._empty_field = empty_field
        self._unset_field = unset_field

    @staticmethod
    def _hexlify(string):
        hex_string = binascii.hexlify(string.encode()).decode()
        return ''.join(map(lambda s: f'\\x{s}', textwrap.wrap(hex_string, 2)))

    def open(self):
        with open(self._file, 'w') as file:
            print(f'#seperator {self._hexlify(self.seperator)}', file=file)
            print(f'#set_separator{self.seperator}{self.set_seperator}', file=file)
            print(f'#empty_field{self.seperator}{self.empty_field}', file=file)
            print(f'#unset_field{self.seperator}{self.unset_field}', file=file)
            print(f'#path{self.seperator}{self.path}', file=file)
            print(f'#open{self.seperator}{time.strftime("%Y-%m-%d-%H-%M-%S")}', file=file)
            print(f'#fields{self.seperator}{self.seperator.join(self._fields.keys())}', file=file)
            print(f'#types{self.seperator}'  # pylint: disable=dict-values-not-iterating
                  f'{self.seperator.join(map(lambda field: field, self._fields.values()))}', file=file)

    def close(self):
        with open(self._file, 'a') as file:
            print(f'#close{self.seperator}{time.strftime("%Y-%m-%d-%H-%M-%S")}', file=file)

    def log(self, model):
        return self.seperator.join(map(lambda field: str(getattr(model, field)), self._fields.keys()))  # pylint: disable=dict-keys-not-iterating
