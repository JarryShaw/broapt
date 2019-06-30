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

from .const import LOGS_PATH

__all__ = [
    # Bro types
    'bro_addr', 'bro_bool', 'bro_count', 'bro_double', 'bro_enum', 'bro_int',
    'bro_interval', 'bro_vector', 'bro_port', 'bro_set', 'bro_string',
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


class LogError(Exception):
    pass


class FieldError(LogError, TypeError):
    pass


class TypingError(LogError, TypeError):
    pass


class ModelError(LogError, ValueError):
    pass


###############################################################################
# Bro logging fields


def _type_check(func):
    @functools.wraps(func)
    def check(self, value):
        if self.predicate(value):
            return func(self, self.cast(value))
        raise FieldError(f'Bro {self.type} is required (got type {type(value).__name__!r})')
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
    __seperator__ = '\x09'
    __set_seperator__ = ','
    __empty_field__ = '(empty)'
    __unset_field__ = '-'

    @property
    def type(self):
        return self.__type__

    @property
    def json(self):
        return self.__use_json__

    @property
    def seperator(self):
        return self.__seperator__

    @property
    def set_seperator(self):
        return self.__set_seperator__

    @property
    def empty_field(self):
        return self.__empty_field__

    @property
    def unset_field(self):
        return self.__unset_field__

    @classmethod
    def set_attributes(cls, *,
                       use_json=False,
                       seperator='\x09',
                       set_seperator=',',
                       empty_field='(empty)',
                       unset_field='-'):
        cls.__use_json__ = use_json
        cls.__seperator__ = seperator
        cls.__set_seperator__ = set_seperator
        cls.__empty_field__ = empty_field
        cls.__unset_field__ = unset_field
        return cls

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        if cls.__type__ is NotImplemented:
            raise NotImplementedError
        return super().__new__(cls)

    def __call__(self, value):
        if self.json:
            return self._to_json(value)
        if value is None:
            return self.unset_field
        return self._to_text(value)

    @classmethod
    def __repr__(cls):
        if hasattr(cls, 'type'):
            return cls.type
        return cls.__type__

    @_type_check
    def _to_json(self, value):
        return self.jsonify(value)

    @_type_check
    def _to_text(self, value):
        return self.textify(value) or self.empty_field


class _SimpleField(_Field):
    pass


class StringField(_SimpleField):

    __type__ = 'string'

    def cast(self, value):  # pylint: disable=no-self-use
        return str(value).encode('unicode-escape').decode()


class PortField(_SimpleField):

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


class EnumField(_SimpleField):

    __type__ = 'enum'

    def predicate(self, value):  # pylint: disable=no-self-use
        return isinstance(value, enum.Enum)

    def cast(self, value):  # pylint: disable=no-self-use
        if isinstance(value, enum.Enum):
            return value.name
        return value


class IntervalField(_SimpleField):

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


class AddrField(_SimpleField):

    __type__ = 'addr'

    def predicate(self, value):  # pylint: disable=no-self-use
        try:
            ipaddress.ip_address(value)
        except (TypeError, ValueError):
            return False
        return True

    def cast(self, value):  # pylint: disable=no-self-use
        return str(ipaddress.ip_address(value))


class SubnetField(_SimpleField):

    __type__ = 'subnet'

    def predicate(self, value):  # pylint: disable=no-self-use
        try:
            ipaddress.ip_network(value)
        except (TypeError, ValueError):
            return False
        return True

    def cast(self, value):  # pylint: disable=no-self-use
        return str(ipaddress.ip_network(value))


class IntField(_SimpleField):

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


class CountField(_SimpleField):

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


class TimeField(_SimpleField):

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


class DoubleField(_SimpleField):

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


class BoolField(_SimpleField):

    __type__ = 'bool'

    def predicate(self, value):  # pylint: disable=no-self-use
        if not isinstance(value, bool):
            warnings.warn(f'cast {type(value).__name__!r} type to bool value', BoolWarning)
        return True

    def jsonify(self, value):  # pylint: disable=no-self-use
        return 'true' if bool(value) else 'false'

    def textify(self, value):  # pylint: disable=no-self-use
        return 'T' if bool(value) else 'F'


class _GenericField(_Field):
    pass


class RecordField(_GenericField):

    __type__ = '~record'

    @property
    def type(self):
        return self.seperator.join(self.__field_type__)

    def __init__(self, value=None, **kwargs):
        if value is None:
            _kw = dict()
        elif dataclasses.is_dataclass(value):
            _kw = dict()
            for field in dataclasses.fields(value):
                if field.default is not dataclasses.MISSING:
                    _kw[field.name] = field.default
                elif field.default_factory is not dataclasses.MISSING:
                    _kw[field.name] = field.default_factory()
                else:
                    _kw[field.name] = field.type
        else:
            _kw = dict(value)
        _kw.update(kwargs)

        self.__field_type__ = list()
        self.__field_factory__ = dict()
        for key, val in _kw.items():
            if isinstance(val, typing.TypeVar):
                val = val.__bound__
            if isinstance(val, _Field):
                field_val = val
            elif isinstance(val, type) and issubclass(val, _SimpleField):
                field_val = val()
            else:
                raise FieldError(f'invalid Bro record field: {val}')
            self.__field_type__.append(field_val.type)
            self.__field_factory__[key] = field_val

    def predicate(self, value):  # pylint: disable=no-self-use
        if dataclasses.is_dataclass(value):
            return True
        try:
            dict(value)
        except (TypeError, ValueError):
            return False
        return False

    def cast(self, value):  # pylint: disable=no-self-use
        if dataclasses.is_dataclass(value):
            value_dict = dataclasses.asdict(value)
        else:
            value_dict = dict(value)

        _value = dict()
        for key, val in self.__field_factory__:
            if key not in value_dict:
                raise FieldError(f'missing field {key!r} in Bro record')
            _value[key] = val(value_dict[key])
        return _value

    def jsonify(self, value):
        return '{%s}' % ', '.join(f'{json.dumps(key)}: {val}' for key, val in value.items())

    def textify(self, value):  # pylint: disable=no-self-use
        if value:
            return self.seperator.join(value.values())
        return self.empty_field


class _SequenceField(_GenericField):

    @property
    def type(self):
        return '%s[%s]' % (self.__type__, self.__field_type__)

    def __init__(self, value):
        if isinstance(value, typing.TypeVar):
            value = value.__bound__

        if isinstance(value, _Field):
            if not self.json and isinstance(value, _GenericField):
                raise FieldError(f'invalid recursive field in ASCII mode: {self.__type__}[{value.__type__}]')
            field_value = value
        elif isinstance(value, type) and issubclass(value, _SimpleField):
            field_value = value()
        else:
            raise FieldError(f'invalid Bro {self.__type__} field')
        self.__field_type__ = field_value.type
        self.__field_factory__ = field_value

    def jsonify(self, value):
        return '[%s]' % ', '.join(value)

    def textify(self, value):
        if value:
            return self.set_seperator.join(value)
        return self.empty_field


class SetField(_SequenceField):

    __type__ = 'set'

    def cast(self, value):
        return set(self.__field_factory__(element) for element in value)


class VectorField(_SequenceField):

    __type__ = 'vector'

    def cast(self, value):
        return list(self.__field_factory__(element) for element in value)


###############################################################################
# Bro logging types

# internal typings
_bro_string = typing.TypeVar('bro_string', bound=StringField)  # _bro_string.__bound__ == StringField
_bro_port = typing.TypeVar('bro_port', bound=PortField)
_bro_enum = typing.TypeVar('bro_enum', bound=EnumField)
_bro_interval = typing.TypeVar('bro_interval', bound=IntervalField)
_bro_addr = typing.TypeVar('bro_addr', bound=AddrField)
_bro_subnet = typing.TypeVar('bro_subnet', bound=SubnetField)
_bro_int = typing.TypeVar('bro_int', bound=IntField)
_bro_count = typing.TypeVar('bro_count', bound=CountField)
_bro_time = typing.TypeVar('bro_time', bound=TimeField)
_bro_double = typing.TypeVar('bro_double', bound=DoubleField)
_bro_bool = typing.TypeVar('bro_bool', bound=BoolField)
_bro_record = typing.TypeVar('bro_record', bound=RecordField)
_bro_set = typing.TypeVar('bro_set', bound=SetField)
_bro_vector = typing.TypeVar('bro_vector', bound=VectorField)
_bro_type = typing.TypeVar('bro_type',  # _bro_type.__constraints__ == (...)
                           _bro_string,
                           _bro_port,
                           _bro_enum,
                           _bro_interval,
                           _bro_addr,
                           _bro_subnet,
                           _bro_int,
                           _bro_count,
                           _bro_time,
                           _bro_double,
                           _bro_bool,
                           _bro_set,
                           _bro_vector,
                           _bro_record)


class _bro_record(typing._SpecialForm, _root=True):  # pylint: disable=protected-access

    def __repr__(self):
        return 'bro_record'

    def __init__(self, name, doc):  # pylint: disable=unused-argument
        super().__init__('bro_record', '')

    @typing._tp_cache  # pylint: disable=protected-access
    def __getitem__(self, parameters):
        if parameters == ():
            raise TypingError('cannot take a Bro record of no types.')
        if not isinstance(parameters, tuple):
            parameters = (parameters,)
        parameters = typing._remove_dups_flatten(parameters)  # pylint: disable=protected-access
        if len(parameters) == 1:
            return parameters[0]
        return typing._GenericAlias(self, parameters)  # pylint: disable=protected-access


class _bro_set(typing.Generic[_bro_type]):
    pass


class _bro_vector(typing.Generic[_bro_type]):
    pass


# basic Bro types
bro_string = _bro_string
bro_port = _bro_port
bro_enum = _bro_enum
bro_interval = _bro_interval
bro_addr = _bro_addr
bro_subnet = _bro_subnet
bro_int = _bro_int
bro_count = _bro_count
bro_time = _bro_time
bro_double = _bro_double
bro_bool = _bro_bool
bro_set = _bro_set
bro_vector = _bro_vector
bro_record = _bro_record()

###############################################################################
# Bro logging data model


class Model(RecordField):

    ###########################################################################
    # APIs for overload

    # def __post_init_prefix__(self):
    #     pass

    def __post_init_suffix__(self):
        pass

    ###########################################################################

    ###########################################################################
    # APIs for overload

    def default(self, field_typing):  # pylint: disable=unused-argument, no-self-use
        return False

    def fallback(self, field_typing):  # pylint: disable=no-self-use
        raise ModelError(f'unknown field type: {field_typing.__name__}')

    ###########################################################################

    # __dataclass_init__ = True
    __dataclass_repr__ = True
    __dataclass_eq__ = True
    __dataclass_order__ = False
    __dataclass_unsafe_hash__ = False
    # __dataclass_frozen__ = True

    @classmethod
    def set_dataclass(cls, *,
                      repr=True,  # pylint: disable=redefined-builtin
                      eq=True,
                      order=False,
                      unsafe_hash=False):
        cls.__dataclass_repr__ = repr
        cls.__dataclass_eq__ = eq
        cls.__dataclass_order__ = order
        cls.__dataclass_unsafe_hash__ = unsafe_hash
        return cls

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        if dataclasses.is_dataclass(cls):
            if cls.__dataclass_params__.frozen:  # pylint: disable=no-member
                raise ModelError('frozen model')
            cls = dataclasses.make_dataclass(cls.__name__,  # pylint: disable=self-cls-assignment
                                             [(field.name, field.type, field) for field in dataclasses.fields(cls)],
                                             bases=cls.__bases__,
                                             namespace=cls.__dict__,
                                             init=True,
                                             repr=cls.__dataclass_repr__,
                                             eq=cls.__dataclass_eq__,
                                             order=cls.__dataclass_order__,
                                             unsafe_hash=cls.__dataclass_unsafe_hash__,
                                             frozen=False)
        else:
            cls = dataclasses._process_class(cls,  # pylint: disable=protected-access, self-cls-assignment
                                             init=True,
                                             repr=cls.__dataclass_repr__,
                                             eq=cls.__dataclass_eq__,
                                             order=cls.__dataclass_order__,
                                             unsafe_hash=cls.__dataclass_unsafe_hash__,
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

    def __call__(self, value=None, **kwargs):  # pylint: disable=arguments-differ
        if value is None:
            value_new = dict()
        elif dataclasses.is_dataclass(value):
            value_new = dataclasses.asdict(value)
        else:
            value_new = dict(value)
        value_new.update(kwargs)
        return super().__call__(value_new)

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
        if field_typing in (bro_vector, bro_set):
            raise FieldError('container Bro type not initialised')
        if hasattr(field_typing, '__supertype__'):
            if field_typing in _bro_type.__constraints__:  # pylint: disable=no-member
                return
            raise FieldError(f'unknown Bro type: {field_typing.__name__}')
        if hasattr(field_typing, '__origin__'):
            if field_typing.__origin__ not in (bro_vector, bro_set):
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
            if field_typing.__origin__ is bro_vector:
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
            if field_typing.__origin__ is bro_vector:
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
