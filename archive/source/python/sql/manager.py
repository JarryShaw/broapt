# -*- coding: utf-8 -*-

from peewee import fn

from .model import Bro_FileDone, Bro_FileTodo, minstr


def getToBeProcessedFile():
    files = Bro_FileTodo.select().where(Bro_FileTodo.status == False)
    output = []
    for file in files:
        output.append(file.path)
    query = Bro_FileTodo.update(status=True).where(Bro_FileTodo.status == False)
    query.execute()
    return output


def deleteToBeProcessedFile(path):
    query = Bro_FileTodo.delete().where(Bro_FileTodo.path == path)
    query.execute()


def updateToBeProcessedFile():
    query = Bro_FileTodo.update(status=False).where(Bro_FileTodo.status == True)
    query.execute()


def saveProcessedFile(file, path):
    tmp = Bro_FileTodo(
        path=path,
        status=False
    )
    tmp.save()
    count = Bro_FileDone.select().count()  # pylint: disable=E1120
    minimum = Bro_FileDone.select(fn.MIN(Bro_FileDone.id)).scalar()  # pylint: disable=E1120
    while count >= 600:
        Bro_FileDone.delete().where(Bro_FileDone.id == minimum).execute()
        minimum += 1
        count = Bro_FileDone.select().count()  # pylint: disable=E1120
    tmp = Bro_FileDone(
        name=file
    )
    tmp.save()


def getProcessedFile():
    file = Bro_FileDone.select(Bro_FileDone.name).where(Bro_FileDone.id == Bro_FileDone.select(fn.MAX(Bro_FileDone.id)).scalar()).dicts()  # pylint: disable=line-too-long
    try:
        return file[0]['name']
    except IndexError:
        return minstr()
