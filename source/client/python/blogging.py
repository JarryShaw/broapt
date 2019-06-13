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


class FrozenError(AttributeError):
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
        raise FieldError(f'{self.type} is required (got type {type(value).__name__!r})')
    return check


class _Field(metaclass=abc.ABCMeta):

    ###########################################################################
    # APIs for overload

    __type__ = NotImplemented

    def jsonify(self, value):  # pylint: disable=no-self-use
        return json.dumps(value)

    def textify(self, value):  # pylint: disable=no-self-use
        return str(value)

    def predicate(self, value):  # pylint: disable=unused-argument, no-self-use
        return True

    def cast(self, value):  # pylint: disable=no-self-use
        return value

    ###########################################################################

    __use_json__ = False

    @property
    def json(self):
        return self.__use_json__

    @property
    def type(self):
        return self.__type__

    @classmethod
    def set_json(cls, use_json):
        cls.__use_json__ = use_json
        return cls

    def __new__(cls, value=None):
        if cls.type is NotImplemented:
            raise NotImplementedError

        if value is None:
            cls.value = value
        elif cls.__use_json__:
            cls.value = cls._to_json(cls, value)
        else:
            cls.value = cls._to_text(cls, value)
        return super().__new__(cls)

    def __setattr__(self, name, value):
        raise FrozenError('cannot assign attributes')

    def __delattr__(self, name):
        raise FrozenError('cannot delete attributes')

    def __str__(self):
        return self.value

    def __repr__(self):
        return f'<{self.type} {self.value}>'

    @_type_check
    def _to_json(self, value):
        return self.jsonify(value)

    @_type_check
    def _to_text(self, value):
        return self.textify(value)


class StringField(_Field):

    __type__ = 'string'

    def cast(self, value):  # pylint: disable=no-self-use
        return str(value).encode('unicode-escape').decode()


class PortField(_Field):

    __type__ = 'port'

    def predicate(self, value):  # pylint: disable=no-self-use
        if isinstance(value, int):
            if 0 <= value <= 65535:
                return True
            return False
        if isinstance(value, ctypes.c_uint16):
            return True
        return False

    def cast(self, value):  # pylint: disable=no-self-use
        if isinstance(value, int):
            return ctypes.c_uint16(value).value
        return value.value


class EnumField(_Field):

    __type__ = 'enum'

    def predicate(self, value):  # pylint: disable=no-self-use
        return isinstance(value, enum.Enum)

    def cast(self, value):  # pylint: disable=no-self-use
        if isinstance(value, enum.Enum):
            return value.name
        return value


class IntervalField(_Field):

    __type__ = 'interval'

    def predicate(self, value):  # pylint: disable=no-self-use
        if isinstance(value, datetime.timedelta):
            return True
        try:
            float(value)
        except (TypeError, ValueError):
            return False
        return True

    def cast(self, value):  # pylint: disable=no-self-use
        if isinstance(value, datetime.timedelta):
            return '%.6f' % value.total_seconds()
        return '%.6f' % float(value)

    def jsonify(self, value):  # pylint: disable=no-self-use
        return '%s%s' % (value[-5], value[-5:].strip('0'))

    def textify(self, value):  # pylint: disable=no-self-use
        return '%s%s' % (value[-5], value[-5:].strip('0'))


class AddrField(_Field):

    __type__ = 'addr'

    def predicate(self, value):  # pylint: disable=no-self-use
        try:
            ipaddress.ip_address(value)
        except (TypeError, ValueError):
            return False
        return True

    def cast(self, value):  # pylint: disable=no-self-use
        return str(ipaddress.ip_address(value))


class SubnetField(_Field):

    __type__ = 'subnet'

    def predicate(self, value):  # pylint: disable=no-self-use
        try:
            ipaddress.ip_network(value)
        except (TypeError, ValueError):
            return False
        return True

    def cast(self, value):  # pylint: disable=no-self-use
        return str(ipaddress.ip_network(value))


class IntField(_Field):

    __type__ = 'int'

    def predicate(self, value):  # pylint: disable=no-self-use
        if isinstance(value, int):
            if int.bit_length(value) > 64:
                warnings.warn(f'{value} exceeds maximum value', IntWarning)
            return True
        if isinstance(value, ctypes.c_int64):
            return True
        return False

    def cast(self, value):  # pylint: disable=no-self-use
        if isinstance(value, int):
            return ctypes.c_int64(value).value
        return value.value


class CountField(_Field):

    __type__ = 'count'

    def predicate(self, value):  # pylint: disable=no-self-use
        if isinstance(value, int):
            if int.bit_length(value) > 64:
                warnings.warn(f'{value} exceeds maximum value', CountWarning)
            if value < 0:
                warnings.warn(f'negative value {value} casts to unsigned', CountWarning)
            return True
        if isinstance(value, ctypes.c_uint64):
            return True
        return False

    def cast(self, value):  # pylint: disable=no-self-use
        if isinstance(value, int):
            return ctypes.c_uint64(value).value
        return value.value


class TimeField(_Field):

    __type__ = 'time'

    def predicate(self, value):  # pylint: disable=no-self-use
        if isinstance(value, datetime.datetime):
            return True
        if isinstance(value, time.struct_time):
            return True
        try:
            float(value)
        except (TypeError, ValueError):
            return False
        return True

    def cast(self, value):  # pylint: disable=no-self-use
        if isinstance(value, datetime.datetime):
            return value.timestamp()
        if isinstance(value, time.struct_time):
            return time.mktime(value)
        return float(value)


class DoubleField(_Field):

    __type__ = 'double'

    def predicate(self, value):  # pylint: disable=no-self-use
        try:
            float(value)
        except (TypeError, ValueError):
            return False
        return True

    def cast(self, value):  # pylint: disable=no-self-use
        return '%.6f' % float(value)

    def jsonify(self, value):  # pylint: disable=no-self-use
        return '%s%s' % (value[-5], value[-5:].strip('0'))

    def textify(self, value):  # pylint: disable=no-self-use
        return '%s%s' % (value[-5], value[-5:].strip('0'))


class BoolField(_Field):

    __type__ = 'bool'

    def predicate(self, value):  # pylint: disable=no-self-use
        if not isinstance(value, bool):
            warnings.warn(f'cast {type(value).__name__!r} type to bool value', BoolWarning)
        return True

    def jsonify(self, value):  # pylint: disable=no-self-use
        return 'true' if bool(value) else 'false'

    def textify(self, value):  # pylint: disable=no-self-use
        return 'T' if bool(value) else 'F'


class RecordField(_Field):

    __type__ = 'record'
    __seperator__ = '\x09'

    @property
    def type(self):
        if self.value is None:
            return self.__type__
        return {key: type(val) for key, val in self.value.items()}

    @classmethod
    def set_type(cls, fields):
        if dataclasses.is_dataclass(fields):
            cls.__type__ = {field.name: field.type for field in dataclasses.fields(fields)}
        else:
            try:
                cls.__type__ = {key: type(val) for key, val in dict(fields).values()}
            except (TypeError, ValueError) as error:
                raise FieldError(f'invalid fields: {error}').with_traceback(error.__traceback__) from None
        return cls

    @classmethod
    def set_separator(cls, seperator):
        cls.__seperator__ = seperator
        return cls

    def predicate(self, value):  # pylint: disable=no-self-use
        if dataclasses.is_dataclass(value):
            return all(map(lambda field: isinstance(field, _Field),
                           dataclasses.asdict(value).values()))
        try:
            return all(map(lambda field: isinstance(field, _Field), dict(value).values()))
        except (TypeError, ValueError):
            return False

    def cast(self, value):  # pylint: disable=no-self-use
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return dict(value)

    def textify(self, value):  # pylint: disable=no-self-use
        return self.__seperator__.join(value.values())


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
bro_record = typing.NewType('bro_record', RecordField)

# generic Bro types
_bro_type = typing.TypeVar('bro_type',
                           bro_string, bro_port, bro_enum, bro_interval,
                           bro_addr, bro_subnet, bro_int, bro_count, bro_time,
                           bro_double, bro_bool, bro_record)


class _bro_list(typing.Generic[_bro_type]):
    pass


class _bro_set(typing.Generic[_bro_type]):
    pass


# container Bro types
bro_list = _bro_list
bro_set = _bro_set

###############################################################################
# Bro logging data model


class _Model(metaclass=abc.ABCMeta):

    ###########################################################################
    # APIs for overload

    def __post_init_prefix__(self):
        pass

    def __post_init_suffix__(self):
        pass

    ###########################################################################

    __use_json__ = False

    @property
    def json(self):
        return self.__use_json__

    @classmethod
    def set_json(cls, use_json):
        cls.__use_json__ = use_json
        return cls

    __Field_repr__ = True
    __Field_eq__ = True
    __Field_order__ = False
    __Field_unsafe_hash__ = False

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        if dataclasses.is_dataclass(cls):
            if cls.__dataclass_params__.frozen:  # pylint: disable=no-member
                raise ModelError('frozen model')
            cls = dataclasses.make_dataclass(cls.__name__,  # pylint: disable=self-cls-assignment
                                             [(field.name, field.type, field) for field in dataclasses.fields(cls)],
                                             bases=cls.__bases__,
                                             namespace=cls.__dict__,
                                             init=True,
                                             repr=cls.__Field_repr__,
                                             eq=cls.__Field_eq__,
                                             order=cls.__Field_order__,
                                             unsafe_hash=cls.__Field_unsafe_hash__,
                                             frozen=False)
        else:
            cls = dataclasses._process_class(cls,  # pylint: disable=protected-access, self-cls-assignment
                                             init=True,
                                             repr=cls.__Field_repr__,
                                             eq=cls.__Field_eq__,
                                             order=cls.__Field_order__,
                                             unsafe_hash=cls.__Field_unsafe_hash__,
                                             frozen=False)
        return super().__new__(cls)

    def __post_init__(self):
        orig_flag = hasattr(self, '__foo')
        if orig_flag:
            orig = getattr(self, '__foo')
        try:
            setattr(self, '__foo', 'foo')
        except dataclasses.FrozenInstanceError as error:
            raise ModelError(f'frozen model: {error}').with_traceback(error.__traceback__) from None
        except Exception:  # pylint: disable=try-except-raise
            raise
        if orig_flag:
            setattr(self, '__foo', orig)
        else:
            delattr(self, '__foo')
        self.__post_init_prefix__()

        for fn in dataclasses._frozen_get_del_attr(self, dataclasses.fields(self)):  # pylint: disable=protected-access
            if dataclasses._set_new_attribute(self, fn.__name__, fn):  # pylint: disable=protected-access
                raise ModelError(f'cannot overwrite attribute {fn.__name__} in class {type(self).__name__}')
        self.__post_init_suffix__()


class Model(_Model):

    ###########################################################################
    # APIs for overload

    def default(self, field_typing):  # pylint: disable=unused-argument, no-self-use
        return False

    def fallback(self, field_typing):  # pylint: disable=no-self-use
        raise ModelError(f'unknown field type: {field_typing.__name__}')

    ###########################################################################

    __seperator__ = '\x09'

    @classmethod
    def set_separator(cls, seperator):
        cls.__seperator__ = seperator
        return cls

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        self = super().__new__(cls, *args, **kwargs)

        __dict__ = dict()
        for key, val in cls.__dict__.items():
            if isinstance(val, type) and issubclass(val, _Field):
                __dict__[key] = val
                cls.__dict__.pop(key)
            if isinstance(val, _Field):
                __dict__[key] = type(val)
                cls.__dict__.pop(key)

        f_name = list()
        fields = list()
        for field in dataclasses.fields(self):
            f_name.append(field.name)
            fields.append((field.name, field.type, field))

        for key, val in __dict__.items():
            if key in f_name:
                continue
            fields.append((key,
                           val,
                           dataclasses.field(repr=cls.__Field_repr__,
                                             hash=cls.__Field_unsafe_hash__,
                                             init=True,
                                             compare=cls.__Field_order__,
                                             metadata=cls.__dict__)))

        cls = dataclasses.make_dataclass(cls.__name__,  # pylint: disable=self-cls-assignment
                                         fields,
                                         bases=cls.__bases__,
                                         namespace=cls.__dict__,
                                         init=True,
                                         repr=cls.__Field_repr__,
                                         eq=cls.__Field_eq__,
                                         order=cls.__Field_order__,
                                         unsafe_hash=cls.__Field_unsafe_hash__,
                                         frozen=False)
        return super(_Model, self).__new__(cls)

    def __post_init_prefix__(self):
        for field in dataclasses.fields(self):
            self._typing_check(field.type)
            value = getattr(self, field.name)
            factory = self._get_factory(field.type)
            setattr(self, field.name, factory(value))

    def _typing_check(self, field_typing):  # pylint: disable=inconsistent-return-statements
        if self.default(field_typing):
            return
        if isinstance(field_typing, type):
            if issubclass(field_typing, _Field):
                return
            raise FieldError(f'unknown Bro type: {field_typing.__name__}')
        if isinstance(field_typing, _Field):
            return
        if field_typing in (bro_list, bro_set):
            raise FieldError('container Bro type not initialised')
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
        if isinstance(field_typing, type) and issubclass(field_typing, _Field):
            factory = field_typing.set_json(use_json=self.json)
            if issubclass(factory, RecordField):
                factory = factory.set_separator(self.__seperator__)
            return factory
        if isinstance(field_typing, _Field):
            factory = type(field_typing).set_json(use_json=self.json)
            if issubclass(factory, RecordField):
                factory = factory.set_separator(self.__seperator__)
            return factory
        if hasattr(field_typing, '__supertype__'):
            supertype = field_typing.__supertype__
            factory = supertype.set_json(use_json=self.json)
            if issubclass(factory, RecordField):
                factory = factory.set_separator(self.__seperator__)
            return factory
        if hasattr(field_typing, '__origin__'):
            if field_typing.__origin__ is bro_set:
                factory = self._get_factory(field_typing.__args__[0]).set_json(use_json=self.json)
                return lambda iterable: set(factory(element) for element in iterable)
            if field_typing.__origin__ is bro_list:
                factory = self._get_factory(field_typing.__args__[0]).set_json(use_json=self.json)
                return lambda iterable: list(factory(element) for element in iterable)
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

    def init(self, file):
        pass

    def exit(self):
        pass

    @abc.abstractmethod
    def log(self, model):
        pass

    def fallback(self, field_typing):  # pylint: disable=no-self-use
        raise ModelError(f'unknown field type: {field_typing.__name__}')

    def __pre_init__(self, path, model, *, log_suffix=None, async_write=True, **kwargs):
        pass

    ###########################################################################

    __seperator__ = '\x09'

    @property
    def path(self):
        return self._path

    def __init__(self, path, model, *, log_suffix=None, async_write=True, **kwargs):  # pylint: disable=unused-argument
        if not issubclass(model, Model):
            raise ModelError(f'type {model.__name__!r} is not a valid model')
        self.__pre_init__(path, model, log_suffix=log_suffix, async_write=async_write, **kwargs)

        if log_suffix is None:
            log_suffix = os.getenv('BROAPT_LOG_SUFFIX', '.log')

        self._model = model.set_separator(self.__seperator__)
        self._field = self._init_field(model)

        self._path = path
        self._file = os.path.join(LOGS_PATH, f'{path}{log_suffix}')

        parents = os.path.split(self._file)[0]
        os.makedirs(parents, exist_ok=True)

        if async_write:
            self._lock = multiprocessing.Lock()
            self.closed = multiprocessing.Value('B', False)
        else:
            self._lock = contextlib.nullcontext()
            self.closed = dataclasses.make_dataclass('closed', [('value', bool, False)])()

        self.open()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _get_name(self, field_typing):
        if isinstance(field_typing, type) and issubclass(field_typing, _Field):
            return (field_typing.__type__, None)
        if isinstance(field_typing, _Field):
            return (field_typing.__type__, None)
        if hasattr(field_typing, '__supertype__'):
            return (field_typing.__supertype__.__type__, None)
        if hasattr(field_typing, '__origin__'):
            if field_typing.__origin__ is bro_set:
                return ('set', self._get_name(field_typing.__args__[0])[0])
            if field_typing.__origin__ is bro_list:
                return ('vector', self._get_name(field_typing.__args__[0])[0])
        return self.fallback(field_typing)

    def _init_field(self, model):
        fields = dict()
        for field in dataclasses.fields(model):
            fields[field.name] = (field.type, self._get_name(field.type))
        return fields

    def _init_model(self, *args, **kwargs):
        if args and isinstance(args[0], self._model):
            dataclass = args[0]
        else:
            dataclass = self._model(*args, **kwargs)
        return dataclasses.asdict(dataclass)

    def open(self):
        with open(self._file, 'w') as file:
            self.init(file)

    def close(self):
        if not self.closed.value:
            with self._lock:
                self.exit()
            self.closed.value = True

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
        self.__seperator__ = seperator

        self._seperator = seperator
        self._set_seperator = set_seperator
        self._empty_field = empty_field
        self._unset_field = unset_field

    @staticmethod
    def _hexlify(string):
        hex_string = binascii.hexlify(string.encode()).decode()
        return ''.join(map(lambda s: f'\\x{s}', textwrap.wrap(hex_string, 2)))

    def _expand_field_names(self):
        fields = list()
        for key, val in self._field.items():
            record = ((val[0] is bro_record) or \
                      (isinstance(val[0], type) and issubclass(val[0], RecordField)) or \
                      isinstance(val[0], RecordField))
            if record:
                fields.extend(f'{key}.{field}' for field in val[1].keys())
            else:
                fields.append(key)
        return fields

    def _expand_field_types(self):
        fields = list()
        for key, val in self._field.items():
            record = ((val[0] is bro_record) or \
                      (isinstance(val[0], type) and issubclass(val[0], RecordField)) or \
                      isinstance(val[0], RecordField))
            if record:
                fields.extend(field for field in val[1].values())
            else:
                fields.append(key)
        return fields

    def init(self, file):
        print(f'#seperator {self._hexlify(self.seperator)}', file=file)
        print(f'#set_separator{self.seperator}{self.set_seperator}', file=file)
        print(f'#empty_field{self.seperator}{self.empty_field}', file=file)
        print(f'#unset_field{self.seperator}{self.unset_field}', file=file)
        print(f'#path{self.seperator}{self.path}', file=file)
        print(f'#open{self.seperator}{time.strftime("%Y-%m-%d-%H-%M-%S")}', file=file)
        print(f'#fields{self.seperator}{self.seperator.join(self._expand_field_names())}', file=file)
        print(f'#types{self.seperator}{self.seperator.join(self._expand_field_types())}', file=file)

    def exit(self):
        with open(self._file, 'a') as file:
            print(f'#close{self.seperator}{time.strftime("%Y-%m-%d-%H-%M-%S")}', file=file)

    def log(self, model):
        return self.seperator.join(map(lambda field: str(getattr(model, field)), self._field.keys()))  # pylint: disable=dict-keys-not-iterating
