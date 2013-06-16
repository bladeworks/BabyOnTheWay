#!/usr/bin/python
# -*- coding: utf8 -*-
import sqlite3
import logging
import os


dbStorage = os.path.join(os.path.dirname(__file__), "db.dat")


def init_database():
    db_execute("""
        create table if not exists user
        (id integer primary key, username text not null unique, password text not null, email text) """)
    db_execute("""
        create table if not exists indicator
        (id integer primary key, username text not null, date text not null, morning_temp real, night_temp real,
         morning_weight real, night_weight real, note text, period_start int, event text) """)


def db_execute(sql, params=[]):
    logging.debug("Execute %s", sql)
    logging.debug("params = %s", params)
    con = sqlite3.connect(dbStorage)
    with con:
        c = con.cursor()
        c.execute(sql, params)
        con.commit()


def db_query(sql, params=[]):
    logging.debug("Query %s", sql)
    logging.debug("params = %s", params)
    con = sqlite3.connect(dbStorage)
    con.row_factory = sqlite3.Row
    with con:
        c = con.cursor()
        c.execute(sql, params)
        d = c.fetchall()
        logging.debug("Query result: %s", d)
        return d


def db_query_one(sql, params=[]):
    logging.debug("Query %s", sql)
    logging.debug("params = %s", params)
    con = sqlite3.connect(dbStorage)
    con.row_factory = sqlite3.Row
    with con:
        c = con.cursor()
        c.execute(sql, params)
        d = c.fetchone()
        logging.debug("Query result: %s", d)
        return d
