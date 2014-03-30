from flask.ext.wtf import Form
from wtforms import TextField, BooleanField, TextAreaField, SelectField, IntegerField, validators
from wtforms.validators import Required, Length
from flask.ext.babel import gettext
from app.models import User

class LoginForm(Form):
    openid = TextField('openid', validators = [Required()])
    remember_me = BooleanField('remember_me', default = False)
    
class EditForm(Form):
    nickname = TextField('nickname', validators = [Required()])
    about_me = TextAreaField('about_me', validators = [Length(min = 0, max = 500)])
    
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
    post = TextAreaField('post', validators = [Required(), Length(min = 1, max = 1000)])
    public = BooleanField('public', default = True)

class AnswerForm(Form):
    answer = TextAreaField('answer', validators = [Required(), Length(min = 1, max = 1000)])

class EmailGroupForm(Form):
    recipients = TextAreaField('recipients', validators = [Required()])

class CommentForm(Form):
    comment = TextAreaField('comment', validators = [Length(min = 1, max = 1000)])
    
class GroupPost(Form):
    group_access = BooleanField('group_access', default = False)

class SearchForm(Form):
    search = TextField('search', validators = [Required(), Length(min = 1, max = 80)])
    search_type = SelectField('search_type', choices=[('User','Nickname or Email'), ('Group', 'Group Name')]) #('Post', 'Prayer Request'), Restrict to only post that user has permission to view.

class ChurchForm(Form):
    church_name = TextField('church_name', validators = [Required(), Length(min = 1, max = 80)])
    about_church = TextAreaField('about_church', validators = [Length(max = 1000)])
    public = BooleanField('public', default = True)
    
class GroupForm(Form):
    group_name = TextField('group_name', validators = [Required(), Length(min = 1, max = 80)])
    about_group = TextAreaField('about_group', validators = [Length(max = 500)])
    public = BooleanField('public', default = True)

class AddressForm(Form):
    datetime = TextField('datetime', validators = [Required(), Length(min = 1, max = 140)])
    address = TextField('address', validators = [Required(), Length(min = 1, max = 140)])
    address2 = TextField('address2', validators = [Length(min = 0, max = 25)])
    city = TextField('city', validators = [Required(), Length(min = 1, max = 80)])
    state = TextField('state', validators = [Required(), Length(min = 1, max = 80)])
    zipcode = IntegerField('zipcode')#, validators = [validators.Regexp("^\d{5}(?:[-\s]\d{4})?$", message = "Must be a valid US zipcode")])
    directions = TextAreaField('directions', validators = [Length(min = 0, max = 500)])


