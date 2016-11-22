#!/usr/bin/env python
import tornado.ioloop
import tornado.web
import sqlite3 as lite
import datetime
import re


def clean_db():
    """Clean Database"""
    con = lite.connect('db.db')
    with con:
        cur = con.cursor()
        tms = datetime.datetime.now() - datetime.timedelta(minutes=5)
        cur.execute("DELETE FROM XXE WHERE ts <=?", (tms,))
        cur.execute("DELETE FROM SSRF WHERE ts <=?", (tms,))
        con.commit()


def create_db():
    """Create Database"""
    con = lite.connect('db.db')
    with con:
        cur = con.cursor()
        cur.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'XXE'")
        tbl_exists = cur.fetchone()[0]
        if tbl_exists == 0:
            cur.execute("CREATE TABLE XXE(payload TEXT, ts timestamp)")
            con.commit()
        cur.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'SSRF'")
        tbl_exists = cur.fetchone()[0]
        if tbl_exists == 0:
            cur.execute("CREATE TABLE SSRF(ip TEXT, ts timestamp)")
            con.commit()


class DeleteByIPHandler(tornado.web.RequestHandler):
    """Delete SSRF Entry by IP"""

    def get(self, pp):
        ip_addr = pp if pp else ''
        con = lite.connect('db.db')
        with con:
            cur = con.cursor()
            cur.execute("DELETE FROM SSRF WHERE ip =?", (ip_addr,))
            con.commit()


class XXECheckHandler(tornado.web.RequestHandler):
    """XXE Check"""

    def get(self, pp):
        xxe = pp if pp else ''
        rmatch = re.match('[0-9a-f]{32}', xxe)
        if rmatch:
            con = lite.connect('db.db')
            with con:
                cur = con.cursor()
                cur.execute("SELECT count(*) FROM XXE WHERE payload=?", (xxe,))
                atk_exists = cur.fetchone()[0]
                if atk_exists == 0:
                    self.write('{"status": "no"}')
                else:
                    self.write('{"status": "yes"}')


class SSRFCheckHandler(tornado.web.RequestHandler):
    """SSRF Check"""

    def get(self, pp):
        ip_addr = pp if pp else ''
        con = lite.connect('db.db')
        with con:
            cur = con.cursor()
            if ip_addr == 'ts':
                # based on timestamp
                tms = datetime.datetime.now() - datetime.timedelta(seconds=30)
                cur.execute("SELECT count(*) FROM SSRF WHERE ts >=?", (tms,))
            else:
                # based on ip
                cur.execute("SELECT count(*) FROM SSRF WHERE ip=?", (ip_addr,))
            atk_exists = cur.fetchone()[0]
            if atk_exists == 0:
                self.write('{"count": 0}')
            else:
                self.write('{"count": ' + str(atk_exists) + '}')


class XXE_SSRFHandler(tornado.web.RequestHandler):
    """XXE and SSRF Handler"""

    def get(self):
        # SSRF and XXE count based
        if self.request.uri == "/":
            self.remote_ip = self.request.headers.get(
                'X-Forwarded-For', self.request.headers.get('X-Real-Ip', self.request.remote_ip))
            tms = datetime.datetime.now()
            con0 = lite.connect('db.db')
            with con0:
                cur = con0.cursor()
                cur.execute("INSERT INTO SSRF VALUES(?,?)",
                            (self.remote_ip, tms))
                self.write("ok")
        # XXE and SSRF hash based url
        tms = datetime.datetime.now()
        payload = (str(self.request.uri)[:33]).replace("/", "")
        rmatch = re.match('[0-9a-f]{32}', payload)
        if rmatch:
            con = lite.connect('db.db')
            with con:
                cur = con.cursor()
                cur.execute("INSERT INTO XXE VALUES(?,?)", (payload, tms))
        self.write(payload)

if __name__ == "__main__":
    create_db()
    tornado.web.Application([
        (r"/ip/(?P<pp>[^\/]+)", SSRFCheckHandler),
        (r"/delete/(?P<pp>[^\/]+)", DeleteByIPHandler),
        (r"/md5/(?P<pp>[^\/]+)", XXECheckHandler),
        (r"/.*", XXE_SSRFHandler),
    ]).listen(8080)
    tornado.ioloop.PeriodicCallback(
        clean_db, 300000).start()  # 15 mins in milliseconds
    tornado.ioloop.IOLoop.instance().start()
    '''
    URI
    1. XXE and SSRF - http://127.0.0.1:8080/<md5>
       Check - http://127.0.0.1:8080/md5/<md5>

    2. SSRF and XXE http://127.0.0.1:8080
       Check - http://127.0.0.1:8080/ip/<ip>   by ip
               http://127.0.0.1:8080/ip/ts     by timestamp
    3. Delete by IP
               http://127.0.0.1:8080/delete/<ip>
    '''
