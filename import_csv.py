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
        indicator['date'] = row[0]
        indicator['username'] = row[1]
        indicator['morning_temp'] = row[2]
        indicator['night_temp'] = row[3]
        indicator['morning_weight'] = row[4]
        indicator['night_weight'] = row[5]
        indicator['note'] = row[6]
        indicator['period_start'] = row[7]
        indicator['event'] = row[8]
        db_execute(insert_sql, indicator)
