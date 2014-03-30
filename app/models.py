from hashlib import md5
from app import db
from app import app
from config import WHOOSH_ENABLED
import re

ROLE_USER = 0
ROLE_ADMIN = 1

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

church_group = db.Table('church_group',
    db.Column('church_id', db.Integer, db.ForeignKey('church.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'))
)

community_group = db.Table('community_group',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id')),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

group_posts = db.Table('group_posts',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id')),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'))
)

church_admins = db.Table('church_admins',
    db.Column('church_id', db.Integer, db.ForeignKey('church.id')),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

group_admins = db.Table('group_admins',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id')),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

group_requests = db.Table('group_requests',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id')),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

class Church(db.Model):
    __searchable__ = ['church_name', 'about_church']

    id = db.Column(db.Integer, primary_key = True)
    church_name = db.Column(db.String(80))
    about_church = db.Column(db.String(1000))
    public = db.Column(db.Boolean())
    locations = db.relationship('ChurchAddress', backref = 'church', lazy = 'dynamic')
    admins = db.relationship('User',
        secondary = 'church_admins',
        backref = db.backref('churchs_admin', lazy = 'dynamic'),
        lazy = 'dynamic')
    # Many to many since group may not be inside a church.
    # Otherwise, FK would force each group to be in a church.  
    groups = db.relationship('Group', 
        secondary = 'church_group',
        backref = db.backref('church', lazy = 'dynamic'),
        lazy = 'dynamic')

    def __repr__(self): # pragma: no cover
        return '<Church %r' % (self.church_name)

class Group(db.Model):
    __searchable__ = ['group_name', 'about_group']

    id = db.Column(db.Integer, primary_key = True)
    group_name = db.Column(db.String(80))
    about_group = db.Column(db.String(500))
    public = db.Column(db.Boolean())
    locations = db.relationship('GroupAddress', backref = 'group', lazy = 'dynamic')
    admins = db.relationship('User',
        secondary = 'group_admins',
        backref = db.backref('groups_admin', lazy = 'dynamic'),
        lazy = 'dynamic')
    users = db.relationship('User',
        secondary = 'community_group',
        backref = db.backref('groups', lazy = 'dynamic'),
        lazy = 'dynamic')
    posts = db.relationship('Post',
        secondary = 'group_posts',
        backref = db.backref('groups', lazy = 'dynamic'),
        lazy = 'dynamic')
    requests = db.relationship('User',
        secondary = 'group_requests',
        backref = db.backref('requests', lazy = 'dynamic'),
        lazy = 'dynamic')

    def add_request(self, user):
        if not self.request_pending(user):
            self.requests.append(user)
            return self

    def remove_request(self, user):
        if self.request_pending(user):
            self.requests.remove(user)
            return self

    def request_pending(self, user):
        return self.requests.filter(group_requests.c.user_id == user.id).count() > 0

    def add_admin(self, user):
        if not self.is_admin(user):
            self.admins.append(user)
            return self

    def is_admin(self, user):
        return self.admins.filter(group_admins.c.user_id == user.id).count() > 0

    def add_user(self, user):
        if not self.in_group(user):
            self.users.append(user)
            return self

    def add_post(self, post):
        if not self.post_in_group(post):
            self.posts.append(post)
            return self

    def post_in_group(self, post):
        return self.posts.filter(group_posts.c.post_id == post.id).count() > 0

    def in_group(self, user):
        return self.users.filter(community_group.c.user_id == user.id).count() > 0

    def __repr__(self): # pragma: no cover
        return '<Group %r>' % (self.group_name)

class User(db.Model):
    __searchable__ = ['nickname', 'email']

    id = db.Column(db.Integer, primary_key = True)
    nickname = db.Column(db.String(64), unique = True)
    email = db.Column(db.String(120), index = True, unique = True)
    role = db.Column(db.SmallInteger, default = ROLE_USER)
    posts = db.relationship('Post', backref = 'author', lazy = 'dynamic')
    about_me = db.Column(db.String(500))
    last_seen = db.Column(db.DateTime)
    followed = db.relationship('User', 
        secondary = followers, 
        primaryjoin = (followers.c.follower_id == id), 
        secondaryjoin = (followers.c.followed_id == id), 
        backref = db.backref('followers', lazy = 'dynamic'), 
        lazy = 'dynamic')
    comments = db.relationship('Comment', backref = 'author', lazy = 'dynamic')

    @staticmethod
    def make_valid_nickname(nickname):
        return re.sub('[^a-zA-Z0-9_\.]', '', nickname)

    @staticmethod
    def make_unique_nickname(nickname):
        if User.query.filter_by(nickname = nickname).first() == None:
            return nickname
        version = 2
        while True:
            new_nickname = nickname + str(version)
            if User.query.filter_by(nickname = new_nickname).first() == None:
                break
            version += 1
        return new_nickname
        
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    def avatar(self, size):
        return 'http://www.gravatar.com/avatar/' + md5(self.email).hexdigest() + '?d=mm&s=' + str(size)
        
    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)
            return self
            
    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)
            return self
            
    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        return Post.query.join(followers, (followers.c.followed_id == Post.user_id)).filter(followers.c.follower_id == self.id).order_by(Post.timestamp.desc())

    def max_groups(self):
        return self.groups.count() > 5

    def __repr__(self): # pragma: no cover
        return '<User %r>' % (self.nickname)    
        
class Post(db.Model):
    __searchable__ = ['subject', 'body', 'answer']
    
    id = db.Column(db.Integer, primary_key = True)
    subject = db.Column(db.String(140))
    body = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    language = db.Column(db.String(5))
    answered = db.Column(db.Boolean())
    answer = db.Column(db.String(1000))
    answer_time = db.Column(db.DateTime)
    comments = db.relationship('Comment', backref = 'op', lazy = 'dynamic')
    public = db.Column(db.Boolean())

    def __repr__(self): # pragma: no cover
        return '<Post %r>' % (self.body)
        
class Comment(db.Model):
    __searchable__ = ['body']

    id = db.Column(db.Integer, primary_key = True)
    body = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    language = db.Column(db.String(5))

    def __repr__(self): # pragma: no cover
        return '<Comment %r>' % (self.body)

class ChurchAddress(db.Model):
    __searchable__ = ['address', 'address2', 'city', 'state', 'zipcode']

    id = db.Column(db.Integer, primary_key = True)
    church_id = db.Column(db.Integer, db.ForeignKey('church.id'))
    datetime = db.Column(db.String(140))
    address = db.Column(db.String(140))
    address2 = db.Column(db.String(25))
    city = db.Column(db.String(80))
    state = db.Column(db.String(80))
    zipcode = db.Column(db.Integer)
    directions = db.Column(db.String(500)) 

    def __repr__(self): # pragma: no cover
        return '<ChurchAddress %r>' % self.address

class GroupAddress(db.Model):
    __searchable__ = ['address', 'address2', 'city', 'state']

    id = db.Column(db.Integer, primary_key = True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    datetime = db.Column(db.String(140))
    address = db.Column(db.String(140))
    address2 = db.Column(db.String(25))
    city = db.Column(db.String(80))
    state = db.Column(db.String(80))
    zipcode = db.Column(db.Integer)
    directions = db.Column(db.String(500))

    def __repr__(self): # pragma: no cover
        return '<GroupAddress %r>' % self.address

if WHOOSH_ENABLED:
    import flask.ext.whooshalchemy as whooshalchemy
    whooshalchemy.whoosh_index(app, User)
    whooshalchemy.whoosh_index(app, Post)
    whooshalchemy.whoosh_index(app, Group)
    whooshalchemy.whoosh_index(app, Church)
    whooshalchemy.whoosh_index(app, ChurchAddress)
    whooshalchemy.whoosh_index(app, GroupAddress)
    whooshalchemy.whoosh_index(app, Comment)
