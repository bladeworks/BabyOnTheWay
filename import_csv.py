#!/usr/bin/python
# -*- coding: utf8 -*-

from database import db_execute
import csv
from app import insert_sql

with open('data.csv', 'rb') as csvfile:
    reader = csv.reader(csvfile)
    reader.next()
    for row in reader:
        indicator = {}
        d = row[1].split('/')
        indicator['date'] = '20%s-%s-%s' % (d[2], d[0], d[1])
        indicator['morning_temp'] = row[2]
        indicator['night_temp'] = row[3]
        indicator['morning_weight'] = row[4]
        indicator['night_weight'] = row[5]
        indicator['username'] = 'snale'
        indicator['note'] = ''
        if row[1] == '05/12/13':
            indicator['period_start'] = '1'
        else:
            indicator['period_start'] = '0'
        db_execute(insert_sql, indicator)
