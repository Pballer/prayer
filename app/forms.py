from flask.ext.wtf import Form
from wtforms import TextField, BooleanField, TextAreaField, SelectField
from wtforms.validators import Required, Length
from flask.ext.babel import gettext
from app.models import User

class LoginForm(Form):
    openid = TextField('openid', validators = [Required()])
    remember_me = BooleanField('remember_me', default = False)
    
class EditForm(Form):
    nickname = TextField('nickname', validators = [Required()])
    about_me = TextAreaField('about_me', validators = [Length(min = 0, max = 140)])
    
    def __init__(self, original_nickname, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.original_nickname = original_nickname
        
    def validate(self):
        if not Form.validate(self):
            return False
        if self.nickname.data == self.original_nickname:
            return True
        if self.nickname.data != User.make_valid_nickname(self.nickname.data):
            self.nickname.errors.append(gettext('This nickname has invalid characters. Please use letters, numbers, dots and underscores only.'))
            return False
        user = User.query.filter_by(nickname = self.nickname.data).first()
        if user != None:
            self.nickname.errors.append(gettext('This nickname is already in use. Please choose another one.'))
            return False
        return True
        
class PostForm(Form):
    subject = TextField('subject', validators = [Required(), Length(min = 1, max = 140)])
    post = TextAreaField('post', validators = [Required(), Length(min = 1, max = 140)])

class CommentForm(Form):
    comment = TextAreaField('comment', validators = [Required(), ])
    
class SearchForm(Form):
    search = TextField('search', validators = [Required(), Length(min = 1, max = 80)])
    search_type = SelectField('search_type', choices=[('User','Nickname or Email'), ('Post', 'Prayer Request')])
