# -*- coding: utf-8 -*-

import functools

import peewee


db = peewee.MySQLDatabase(
    database='bro',
    host='bro_db',
    port=3306,
    user='root',
    passwd='zft13917331612',
    charset='utf8',
)


@functools.total_ordering
class minstr:
    def __gt__(self, other):
        return False


class BaseModel(peewee.Model):
    class Meta:
        database = db


class Bro_FileDone(BaseModel):
    name = peewee.CharField(max_length=255)


class Bro_FileTodo(BaseModel):
    path = peewee.CharField(max_length=255)
    status = peewee.BooleanField()
