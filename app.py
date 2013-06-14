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

fields = ("date", "username", "morning_temp", "night_temp", "morning_weight", "night_weight", "note", "period_start",)
update_sql = "update indicator set %s where id = :id" % ", ".join(["%s = :%s" % (f, f) for f in fields])
insert_sql = "insert into indicator(%s) values(%s)" % (", ".join(fields), ", ".join([":%s" % f for f in fields]))


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


class SignupHandler(BaseHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
        username = self.get_argument("username")
        password = self.get_argument("password")
        db_execute("insert into user(username, password) values(?, ?)", [username, sha256_crypt.encrypt(password)])
        self.set_secure_cookie('user', username)
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
    def get(self):
        # Get the latest period start
        sql = "select date from indicator where period_start = ? and username = ? order by date desc limit 1"
        res = db_query_one(sql, [1, self.current_user])
        indicators = []
        if res:
            sql = "select * from indicator where date >= ? and username = ? order by date desc"
            indicators = db_query(sql, [res["date"], self.current_user])
        self.render("index.html", indicators=indicators)


class EditHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, id=None):
        indicator = dict()
        if id:
            r = db_query_one("select * from indicator where id = ? and username = ?", [id, self.current_user])
            for f in r.keys():
                indicator[f] = r[f]
        self.render("edit.html", indicator=indicator)

    def post(self, id=None):
        indicator = dict()
        for param_name in fields:
            if param_name == "username":
                indicator[param_name] = self.current_user
            else:
                indicator[param_name] = self.get_argument(param_name)
        logging.debug("indicator = %s", indicator)
        if id:
            indicator["id"] = id
            db_execute(update_sql, indicator)
        else:
            db_execute(insert_sql, indicator)
        self.redirect("/")


class DeleteHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, id):
        db_execute("delete from indicator where id = ?", [id])
        self.redirect('/')


class ChartHandler(tornado.web.RequestHandler):
    def get(self, indicators):
        pass


settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
    "template_path": os.path.join(os.path.dirname(__file__), "template"),
    "cookie_secret": "NOIDFSFFKDFJLJLJ",
    "login_url": "/login",
    "debug": True,
}

app = tornado.web.Application([
    (r'/', MainHandler),
    (r'/add', EditHandler),
    (r'/edit', EditHandler),
    (r'/edit/(\d+)', EditHandler),
    (r'/delete/(\d+)', DeleteHandler),
    (r'/chart/(\w+)', ChartHandler),
    (r'/signup', SignupHandler),
    (r'/login', LoginHandler),
    (r'/logout', LogoutHandler),
], **settings)


if __name__ == '__main__':
    parse_command_line()
    logging.getLogger().setLevel(logging.DEBUG)
    init_database()
    app.listen(8888, "0.0.0.0")
    tornado.ioloop.IOLoop.instance().start()
