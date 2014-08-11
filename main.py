import os
import re
import logging
import urllib2
import hmac
import webapp2
import jinja2

from bcrypt import bcrypt
from google.appengine.api import memcache
from google.appengine.ext import db

user_regex = re.compile(r"^[a-zA-Z0-9\._-]{3,20}$") 
pass_regex = re.compile(r"^.{3,20}$")
email_regex = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True) 

secret = "DanBongo"

# Field verification tools
def verify_user(username):
    return user_regex.match(username)

def verify_pass(password):
    return pass_regex.match(password)

def verify_email(email):
    return not email or email_regex.match(email)

# Make and check secure values
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# user stuff
def make_pw_hash(name, pw, salt = bcrypt.gensalt(5)):
    h = bcrypt.hashpw(str(name + pw + salt), salt)
    return '%s|%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class Users(db.Model):
    name = db.StringProperty(required=True)
    pass_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = Users.all().filter('name =', name).ancestor(users_key()).get()
        return u

    @classmethod
    def register(cls, name, pwd, email = None):
        pwd_hash = make_pw_hash(name, pwd)
        return cls(parent = users_key(), name = name, pass_hash = pwd_hash, email = email)

    @classmethod
    def login(cls, name, pwd):
        u = cls.by_name(name)
        if u and valid_pw(name, pwd, u.pass_hash):
            return u


def wiki_key(name = 'default'):
    return db.Key.from_path('wikis', name)

class Wikis(db.Model):
    content = db.TextProperty(required=True)
    url = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_updated = db.DateTimeProperty(auto_now=True)

    @staticmethod
    def parent_key(url):
        return db.Key.from_path('/root' + url, 'wikis')

    @classmethod
    def by_url(cls, url):
        q = cls.all().ancestor(cls.parent_key(url)).order('-created')
        return q

    @classmethod
    def by_id(cls, page_id, url):
        return cls.get_by_id(page_id, cls.parent_key(url))

class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def rendera_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.rendera_str(template, **kw))

    # Method for setting a cookie(takes in a username)
    def make_cookie(self, name, val):
        user_secure = str(make_secure_val(val))
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, user_secure))

    def read_cookie(self, c):
        user_cookie = self.request.cookies.get(c)
        return user_cookie and check_secure_val(user_cookie)

    def referer(self):
        ref = self.request.headers.get('referer', '/')
        return ref

    def login(self, user):
        self.make_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and Users.by_id(int(uid))


def all_wikis(url, update=False):
    key = 'wikis-' + url
    wikis = memcache.get(key)
    if wikis is None or update:
        logging.error("DB QUERY")
        wikis = Wikis.by_url(url).get()
        memcache.set(key, wikis)
    return wikis

class SignUpPage(WikiHandler):
    def get(self):
        next_url = self.referer()
        self.render('registration.html', next_url = next_url)

    def post(self):
        has_error = False

        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login'):
            next_url = '/'

        self.name = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.name, email = self.email)

        if not verify_user(self.name):
            params['error_user'] = "That is not a valid username."
            has_error = True

        if not verify_pass(self.password):
            params['error_pass'] = "That is not a valid password."
            has_error = True
        elif not self.password == self.verify:
            params['error_verify'] = "Those passwords don't match."
            has_error = True

        if not verify_email(self.email):
            params['error_email'] = "That email is not valid."
            has_error = True

        if has_error:
            self.render('registration.html', **params)
        else: 
            user = Users.all().filter('name =', self.name).get()
            if user:
                params['error_user'] = "That user already exists."
                self.render('registration.html', **params)
            else:
                user = Users.register(self.name, self.password, self.email)
                user.put()
                
                self.login(user)
                self.redirect(next_url)

class LoginPage(WikiHandler):
    def get(self):
        next_url = self.referer()
        self.render('login.html', next_url = next_url)

    def post(self):
        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login') or next_url.startswith('/signup'):
            next_url = '/'

        self.username = self.request.get('username')
        self.password = self.request.get('password')

        user = Users.login(self.username, self.password)
        if user:
            self.login(user)
            self.redirect(next_url)
        else:
            error = "Invalid login credentials."
            self.render('login.html', error_login = error)

class LogoutPage(WikiHandler):
    def get(self):
        next_url = self.referer()
        self.logout()
        self.redirect(next_url)


class FrontPage(WikiHandler):
    def get(self, page):
        v = self.request.get('v')
        wiki = None

        if not page:
            page = '/'

        params = dict(user = self.user if self.user else None, url = page)

        if v:
            if v.isdigit():
                wiki = Wikis.by_id(int(v), page)
                params['page_id'] = v

            if not wiki:
                self.error(400)
        else:
            wiki = Wikis.by_url(page).get()

        if not wiki:
            logging.error("CREATING FRONT")
            wiki = Wikis(parent = Wikis.parent_key(page), content = '<h1>Welcome to PseudoWiki!</h1>', url = page)
            wiki.put()

        params['page'] = wiki

        self.render('front.html', **params)


class EditPage(WikiHandler):
    def get(self, page):
        if not self.user:
            self.redirect('/login')

        params = dict(user = self.user, url = page)

        v = self.request.get('v')
        wiki = None
        if v:
            if v.isdigit():
                wiki = Wikis.by_id(int(v), page)
                params['page_id'] = v

            if not wiki:
                self.error(400)

        else:
            wiki = Wikis.by_url(page).get()
        
        if wiki:
            params['page'] = wiki 
            
        self.render('edit.html', **params)

    def post(self, page):
        self.page = page if page else '/'
        change = False

        self.content = self.request.get('content')
        wiki = all_wikis(self.page)

        if not (wiki and self.content):
            pass
        elif not wiki or wiki.content != self.content:
            wiki = Wikis(parent = Wikis.parent_key(self.page), content = self.content, url = self.page)
            wiki.put()
            change = True

        if change:
            all_wikis(self.page, True)

        self.redirect(self.page)


class WikiPage(WikiHandler):
    def get(self, page):
        params = dict(user = self.user if self.user else None, url = page)

        v = self.request.get('v')
        wiki = None
        if v:
            if v.isdigit():
                wiki = Wikis.by_id(int(v), page)
                params['page_id'] = v

            if not wiki:
                self.error(400)
        else:
            wiki = Wikis.by_url(page).get()

        if wiki:
            params['page'] = wiki
            self.render('wiki.html', **params)
        else:
            if self.user:
                self.redirect('/_edit' + page)
            else:
                self.redirect('/login')

class HistoryPage(WikiHandler):
    def get(self, page):
        if not page:
            page = '/'

        wikis_hist = Wikis.by_url(page).fetch(limit = 100)

        self.render('history.html', url = page, user = self.user if self.user else None, wikis = wikis_hist)

PAGE_RE = r'(/*(?:[a-zA-Z0-9_-]+/?)*)'
V_RE = r'((?:v%3F%3D[\d+])*)'
app = webapp2.WSGIApplication([
                               ('/signup', SignUpPage),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage), 
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               ('/' + V_RE, FrontPage),
                               (PAGE_RE, WikiPage)
                              ], debug=True)