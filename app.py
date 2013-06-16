#!/usr/bin/python
# -*- coding: utf8 -*-

import tornado.ioloop
import tornado.web
import tornado.escape
import os
import logging
from tornado.options import parse_command_line
from database import db_execute, db_query, init_database, db_query_one
from passlib.hash import sha256_crypt

fields = ("date", "username", "morning_temp", "night_temp", "morning_weight", "night_weight", "note", "period_start", "event")
update_sql = "update indicator set %s where id = :id" % ", ".join(["%s = :%s" % (f, f) for f in fields])
insert_sql = "insert into indicator(%s) values(%s)" % (", ".join(fields), ", ".join([":%s" % f for f in fields]))

fields_user = ("username", "password", "email", "event_map")
update_sql_user = "update user set %s where username = :username" % ", ".join(["%s = :%s" % (f, f) for f in [field for field in fields_user if field not in ["username", "password"]]])
insert_sql_user = "insert into user(%s) values(%s)" % (", ".join(fields_user), ", ".join([":%s" % f for f in fields_user]))


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("user")

    def set_flash_message(self, key, message):
        logging.debug("Set %s: %s", key, message)
        self.set_secure_cookie("flash_msg_%s" % key, message)

    def get_flash_message(self, key):
        val = self.get_secure_cookie('flash_msg_%s' % key)
        self.clear_cookie('flash_msg_%s' % key)
        return val

    def get_event_map(self):
        r = db_query_one("select event_map from user where username = ?", [self.current_user])
        if r:
            return r['event_map'].split(',')


class SignupHandler(BaseHandler):
    def get(self, username=None):
        if username and username != self.current_user:
            self.set_flash_message("error", "You are not %s so force to logout!" % username)
            self.redirect('/logout')
        user = {}
        if username:
            r = db_query_one("select * from user where username = ?", [self.current_user])
            for f in [k for k in r.keys() if k != 'password']:
                user[f] = r[f]
            for idx, v in enumerate(user['event_map'].split(',')):
                user["event%s" % (idx + 1)] = v
        self.render("signup.html", user=user)

    def post(self, username=None):
        user = {}
        for f in [field for field in fields_user if field != "event_map"]:
            if username and f == "password":
                continue
            user[f] = self.get_argument(f)
        user["event_map"] = ",".join([self.get_argument("event%s" % i) for i in range(1, 4)])
        if not username:
            user["password"] = sha256_crypt.encrypt(user["password"])
        try:
            if username:
                db_execute(update_sql_user, user)
            else:
                db_execute(insert_sql_user, user)
        except Exception as e:
            logging.exception("Got exception while adding user")
            if e.message == "column username is not unique":
                self.set_flash_message("error", "The user with name %s is existed." % user["username"])
                self.redirect('/signup')
            else:
                raise e
        else:
            self.set_secure_cookie('user', user["username"])
            self.redirect('/')


class LoginHandler(BaseHandler):
    def get(self):
        self.render("login.html", next=self.get_argument("next", "/"))

    def post(self):
        username = self.get_argument("username")
        password = self.get_argument("password")
        user = db_query_one("select * from user where username = ?", [username])
        if user:
            if sha256_crypt.verify(password, user['password']):
                logging.info("User %s login successfully.", username)
                self.set_secure_cookie('user', username)
                self.redirect(self.get_argument("next", "/"))
                return
        logging.info("User %s login failed.", username)
        self.set_flash_message('error', 'Incorrect username/password.')
        self.redirect('/login')


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect("/login")


class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, start_date=None):
        # Get the latest period start
        logging.info("start_date = %s", start_date)
        sql = "select date from indicator where period_start = ? and username = ? order by date asc"
        res = db_query(sql, [1, self.current_user])
        start_list = [r['date'] for r in res]
        indicators = []
        end_date = '9999-12-30'
        previous_date, next_date = None, None
        y_max_t = 0
        y_min_t = 999
        y_max_w = 0
        y_min_w = 999
        events = []
        if start_list:
            if not start_date:
                start_date = start_list[-1]
                if len(start_list) > 1:
                    previous_date = start_list[-2]
            else:
                idx = start_list.index(start_date)
                if idx < (len(start_list) - 1):
                    end_date = start_list[idx + 1]
                    next_date = end_date
                if idx > 0:
                    previous_date = start_list[idx - 1]
            sql = "select * from indicator where date >= ? and date < ? and username = ? order by date desc"
            res = db_query(sql, [start_date, end_date, self.current_user])
            for row in res:
                indicator = {}
                for k in row.keys():
                    if 'temp' in k or 'weight' in k:
                        indicator[k] = float(row[k]) if row[k] else row[k]
                    elif k == 'event':
                        if row[k] and row[k] != '000':
                            date_parts = row['date'].split('-')
                            date_display_parts = []
                            for idx, v in enumerate(row[k]):
                                if v == '1':
                                    events.append(row['date'])
                                    date_display_parts.append('<span class="event%s">%s</span>' % ((idx + 1), date_parts[idx]))
                                else:
                                    events.append('')
                                    date_display_parts.append(date_parts[idx])
                            indicator["date_display"] = "-".join(date_display_parts)
                    else:
                        indicator[k] = row[k]
                for t in ('morning_temp', 'night_temp'):
                    if indicator[t]:
                        y_max_t = max(y_max_t, float(indicator[t]))
                        y_min_t = min(y_min_t, float(indicator[t]))
                for w in ('morning_weight', 'night_weight'):
                    if indicator[w]:
                        y_max_w = max(y_max_w, float(indicator[w]))
                        y_min_w = min(y_min_w, float(indicator[w]))
                indicators.append(indicator)
            y_max_t += 0.1
            y_min_t -= 0.1
            y_max_w += 0.2
            y_min_w -= 0.2
        if events:
            holder = ""
            extra = []
            for e in events[:3]:
                extra.append(e)
                if e:
                    holder = e
                    break
            events.extend(extra)
            for idx, v in enumerate(events):
                if not v:
                    events[idx] = holder
        self.render("index.html", indicators=indicators, previous_date=previous_date,
                    next_date=next_date, start_list=start_list, y_max_t=y_max_t,
                    y_min_t=y_min_t, y_max_w=y_max_w, y_min_w=y_min_w,
                    start_date=start_date, event_map=self.get_event_map(),
                    events=events)


class EditHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, id=None):
        indicator = dict()
        if id:
            r = db_query_one("select * from indicator where id = ? and username = ?", [id, self.current_user])
            for f in r.keys():
                if f == "event":
                    for idx, v in enumerate(r[f]):
                        indicator['event%s' % (idx + 1)] = int(v)
                else:
                    indicator[f] = r[f]
        logging.debug("indicator = %s", indicator)
        self.render("edit.html", indicator=indicator, event_map=self.get_event_map())

    def post(self, id=None):
        indicator = dict()
        for param_name in fields:
            if param_name == "username":
                indicator[param_name] = self.current_user
            elif param_name == "event":
                indicator[param_name] = "".join([self.get_argument('event%s' % i) for i in range(1, 4)])
            else:
                indicator[param_name] = self.get_argument(param_name)
        logging.debug("indicator = %s", indicator)
        if id:
            indicator["id"] = id
            db_execute(update_sql, indicator)
            self.redirect("/")
        else:
            try:
                db_execute(insert_sql, indicator)
            except Exception as e:
                logging.exception("Got exception while adding record.")
                if e.message == "column date is not unique":
                    self.set_flash_message("error", "The record for %s is existed." % indicator['date'])
                    self.redirect('/add')
                else:
                    raise e
            else:
                self.redirect("/")


class DeleteHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, id):
        db_execute("delete from indicator where id = ?", [id])
        self.redirect('/')


class ExportHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, format="csv"):
        if format == 'csv':
            self.set_header('Content-Type', 'text/csv')
            self.set_header('Content-Disposition', 'attachment; filename=export.csv')
            self.write(','.join(fields) + '\n')
            sql = "select %s from indicator where username = ?" % ", ".join(fields)
            indicators = db_query(sql, [self.current_user])
            for indicator in indicators:
                self.write(",".join([str(indicator[f]) for f in fields]) + "\n")
        else:
            self.write("Unimplemented export")


settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
    "template_path": os.path.join(os.path.dirname(__file__), "template"),
    "cookie_secret": "Bz/WKEQGTh+ge7e4+J0GOpFfjFh1BUlFg/RWKweu7fw=",
    "login_url": "/login",
    "debug": True,
}

app = tornado.web.Application([
    (r'/', MainHandler),
    (r'/period/(\d{4}-\d+-\d+)', MainHandler),
    (r'/add', EditHandler),
    (r'/edit', EditHandler),
    (r'/edit/(\d+)', EditHandler),
    (r'/delete/(\d+)', DeleteHandler),
    (r'/signup', SignupHandler),
    (r'/preference/(\w+)', SignupHandler),
    (r'/login', LoginHandler),
    (r'/logout', LogoutHandler),
    (r'/export/(\w+)', ExportHandler),
], **settings)


if __name__ == '__main__':
    parse_command_line()
    logging.getLogger().setLevel(logging.DEBUG)
    init_database()
    app.listen(8888, "0.0.0.0")
    tornado.ioloop.IOLoop.instance().start()
