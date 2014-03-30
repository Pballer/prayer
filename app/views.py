from flask import render_template, flash, redirect, session, url_for, request, g, jsonify
from flask.ext.login import login_user, logout_user, current_user, login_required
from flask.ext.sqlalchemy import get_debug_queries
from flask.ext.babel import gettext
from app import app, db, lm, oid, babel
from forms import LoginForm, EditForm, PostForm, SearchForm, CommentForm, AnswerForm, GroupForm, GroupPost, AddressForm, EmailGroupForm
from models import User, ROLE_USER, ROLE_ADMIN, Post, Comment, Group, Church, GroupAddress
from datetime import datetime
from emails import follower_notification, group_invite
from guess_language import guessLanguage
from translate import microsoft_translate
from config import POSTS_PER_PAGE, MAX_SEARCH_RESULTS, LANGUAGES, DATABASE_QUERY_TIMEOUT, WHOOSH_ENABLED

@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

@babel.localeselector
def get_locale():
    headers = request.headers.get('User-Agent')
    app.logger.info('Header info: ' + headers)
    return request.accept_languages.best_match(LANGUAGES.keys()) or 'en'
    
@app.before_request
def before_request():
    g.user = current_user
    if g.user.is_authenticated():
        g.user.last_seen = datetime.utcnow()
        db.session.add(g.user)
        db.session.commit()
        g.search_form = SearchForm()
    g.locale = get_locale()
    g.search_enabled = WHOOSH_ENABLED

@app.after_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= DATABASE_QUERY_TIMEOUT:
            app.logger.warning("SLOW QUERY: %s\nParameters: %s\nDuration: %fs\nContext: %s\n" % (query.statement, query.parameters, query.duration, query.context))
    return response

@app.errorhandler(404)
def internal_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.route('/', methods = ['GET', 'POST'])
@app.route('/index', methods = ['GET', 'POST'])
@app.route('/index/<int:page>', methods = ['GET', 'POST'])
def index(page = 1):
    posts = Post.query.filter(Post.public == True).order_by(Post.timestamp.desc()).paginate(page, POSTS_PER_PAGE, False)    
    return render_template('index.html',
        title = 'Home',
        posts = posts)

@app.route('/post-prayer', methods = ['GET', 'POST'])
@login_required
def post_prayer():
    form = PostForm()
    group_forms = [(group, GroupPost(prefix = str(group.id))) for group in g.user.groups]
    if form.validate_on_submit():
        language = guessLanguage(form.post.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''
        post = Post(subject = form.subject.data,
            body = form.post.data,
            timestamp = datetime.utcnow(),
            author = g.user,
            language = language,
            public = form.public.data)
        db.session.add(post)
        db.session.commit()
        if not post.public:
            # Filter only group that were selected.
            add_groups = filter(lambda g: g[1].group_access.data == True, group_forms)
            for group in add_groups:
                group[0].add_post(post)
                db.session.add(group[0])
            db.session.commit()   
        flash(gettext('Your post is now live!'))
        return redirect(url_for('post', id = post.id))
    return render_template('post_form.html',
        title = 'Post Prayer',
        form = form,
        group_forms = group_forms)


@app.route('/group/<int:group_id>')
@app.route('/group/<int:group_id>/<int:page>')
@login_required
def group(group_id, page = 1):
    posts = [] # Set as empty incase user is not in group.
    group = Group.query.get(group_id)
    if group == None:
        flash("Group not found.")
        return redirect(url_for('index'))
    if group.in_group(g.user):
        posts = Post.query.filter((Post.id.in_([post.id for post in [list(u.posts) for u in group.users] for post in post if post.public == True])) | (Post.id.in_([p.id for p in group.posts]))).order_by(Post.timestamp.desc()).paginate(page, POSTS_PER_PAGE, False)
    addresses = group.locations
    return render_template('group.html',
        title = group.group_name,
        posts = posts,
        group = group,
        addresses = addresses)

@app.route('/email-group/<int:group_id>', methods = ['GET', 'POST'])
@login_required
def email_group(group_id):
    group = Group.query.get(group_id)
    if group == None:
        flash("Group not found.")
        return redirect(url_for('index'))
    if not group.is_admin(g.user):
        flash("You are not an admin of this group")
        return redirect(url_for('index'))
    form = EmailGroupForm()
    if form.validate_on_submit():
        group_invite(group, form.recipients.data.split(','))
        flash(gettext('Your email has been sent!'))
        return redirect(url_for('group_admin', 
            group_id = group.id))
    return render_template('email_group.html',
        title = 'Email - {0}'.format(group.group_name),
        form = form)

@app.route('/full-group-info/<int:group_id>', methods = ['GET', 'POST'])
@login_required
def full_group_info(group_id):
    group = Group.query.get(group_id)
    addresses = []
    if group == None:
        flash("Group not found.")
        return redirect(url_for('index'))
    if group.in_group(g.user):
        addresses = group.locations.all()
    return render_template('group_info_full.html',
        title = group.group_name,
        group = group,
        addresses = addresses)

@app.route('/my-groups', methods = ['GET', 'POST'])
@login_required
def my_groups():
    groups = g.user.groups
    return render_template('my_groups.html',
        title = 'My Groups',
        groups = groups)

@app.route('/group-members/<int:group_id>', methods = ['GET'])
@login_required
def group_members(group_id):
    group = Group.query.get(group_id)
    if group == None:
        flash("Group not found.")
        return redirect(url_for('index'))
    members = group.users
    return render_template('group_members.html',
        title = 'Group Members {0}'.format(group.group_name),
        group = group,
        members = members)

@app.route('/group-admin-page/<int:group_id>', methods = ['GET', 'POST'])
@login_required
def group_admin(group_id):
    group = Group.query.get(group_id)
    if group == None:
        flash("Group not found.")
        return redirect(url_for('index'))
    if not group.is_admin(g.user):
        flash("You are not an admin of this group")
        return redirect(url_for('index'))
    return render_template('group_admin.html', 
        title = "Admin - {0}".format(group.group_name),
        group = group)

@app.route('/pending-requests/<int:group_id>', methods = ['GET', 'POST'])
@login_required
def group_requests(group_id):
    group = Group.query.get(group_id)
    if group == None:
        flash("Group not found.")
        return redirect(url_for('index'))
    if not group.is_admin(g.user):
        flash("You are not an admin of this group")
        return redirect(url_for('index'))
    pending_requests = group.requests.all()
    return render_template('group_admin_requests.html',
        title = 'Group Admin Page',
        group = group,
        pending_requests = pending_requests)

@app.route('/add-group-address/<int:group_id>', methods = ['GET', 'POST'])
@login_required
def add_group_address(group_id):
    group = Group.query.get(group_id)
    if group == None:
        flash("Group not found.")
        return redirect(url_for('index'))
    if not group.is_admin(g.user):
        flash("You are not an admin of this group")
        return redirect(url_for('index'))
    form = AddressForm()
    if form.validate_on_submit():
        group_address = GroupAddress(group = group,
            datetime = form.datetime.data,
            address = form.address.data,
            address2 = form.address2.data,
            city = form.city.data,
            state = form.state.data,
            zipcode = form.zipcode.data,
            directions = form.directions.data)
        db.session.add(group_address)
        db.session.commit()
        flash(gettext('Address was added to your group.'))
        return redirect(url_for('group', group_id = group_id))
    return render_template('add_address.html',
        title = "Add address - {0}".format(group.group_name),
        form = form)

@app.route('/group-approve-user/<nickname>/<int:group_id>/<approve>', methods = ['GET', 'POST'])
@login_required
def group_approve_user(nickname, group_id, approve):
    user = User.query.filter_by(nickname = nickname).first()
    if user == None:
        flash(gettext('User %(nickname)s not found.', nickname = nickname))
        return redirect(url_for('index'))
    group = Group.query.get(group_id)
    if group == None:
        flash("Group not found.")
        return redirect(url_for('index'))
    if not group.is_admin(g.user):
        flash("You are not an admin of this group")
        return redirect(url_for('index'))
    if group.in_group(user):
        flash("User is already in group.")
        return redirect(url_for('index'))
    if approve:
        group.add_user(user)
        flash("User was added to group!.")
    else:
        flash("User was not added to the group.")
    group.remove_request(user)
    db.session.add(group)
    db.session.commit()
    pending_requests = group.requests.all()
    return render_template('group_admin_requests.html',
        title = 'Group Admin Page',
        group = group,
        pending_requests = pending_requests)

@app.route('/create-group', methods = ['GET', 'POST'])
@login_required
def create_group():
    if g.user.max_groups():
        flash(gettext('How many groups do you need to be in? Only 5 for you :)'))
        return redirect(url_for('index'))
    form = GroupForm()
    if form.validate_on_submit():
        group = Group(group_name = form.group_name.data,
            about_group = form.about_group.data,
            public = form.public.data)
        db.session.add(group)
        db.session.commit()
        # Create group, add creator to admin and user list.
        db.session.add(group.add_admin(g.user))
        db.session.add(group.add_user(g.user))
        db.session.commit()
        flash('Welcome to your new group!  Now add some friends!')
        return redirect(url_for('group', group_id = group.id))
    return render_template('group_form.html',
        title = 'Create Group',
        form = form)

@app.route('/login', methods = ['GET', 'POST'])
@oid.loginhandler
def login():
    if g.user is not None and g.user.is_authenticated():
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        session['remember_me'] = form.remember_me.data
        return oid.try_login(form.openid.data, ask_for = ['nickname', 'email'])
    return render_template('login.html', 
        title = 'Sign In',
        form = form,
        providers = app.config['OPENID_PROVIDERS'])

@oid.after_login
def after_login(resp):
    if resp.email is None or resp.email == "":
        flash(gettext('Invalid login. Please try again.'))
        return redirect(url_for('login'))
    user = User.query.filter_by(email = resp.email).first()
    if user is None:
        nickname = resp.nickname
        if nickname is None or nickname == "":
            nickname = resp.email.split('@')[0]
        nickname = User.make_valid_nickname(nickname)
        nickname = User.make_unique_nickname(nickname)
        user = User(nickname = nickname, email = resp.email, role = ROLE_USER)
        db.session.add(user)
        db.session.commit()
        # make the user follow him/herself
        db.session.add(user.follow(user))
        db.session.commit()
    remember_me = False
    if 'remember_me' in session:
        remember_me = session['remember_me']
        session.pop('remember_me', None)
    login_user(user, remember = remember_me)
    return redirect(request.args.get('next') or url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
    
@app.route('/user/<nickname>')
@app.route('/user/<nickname>/<int:page>')
@login_required
def user(nickname, page = 1):
    user = User.query.filter_by(nickname = nickname).first()
    if user == None:
        flash(gettext('User %(nickname)s not found.', nickname = nickname))
        return redirect(url_for('index'))
    if user.id == g.user.id:
        posts = user.posts.order_by(Post.timestamp.desc()).paginate(page, POSTS_PER_PAGE, False)
    else:
        posts = user.posts.filter(Post.public == True).order_by(Post.timestamp.desc()).paginate(page, POSTS_PER_PAGE, False)
    return render_template('user.html',
        user = user,
        posts = posts)

@app.route('/edit', methods = ['GET', 'POST'])
@login_required
def edit():
    form = EditForm(g.user.nickname)
    if form.validate_on_submit():
        g.user.nickname = form.nickname.data
        g.user.about_me = form.about_me.data
        db.session.add(g.user)
        db.session.commit()
        flash(gettext('Your changes have been saved.'))
        return redirect(url_for('edit'))
    elif request.method != "POST":
        form.nickname.data = g.user.nickname
        form.about_me.data = g.user.about_me
    return render_template('edit.html',
        form = form)

@app.route('/edit-post/<int:id>', methods = ['GET', 'POST'])
@app.route('/edit-post/<int:id>/<int:page>/', methods = ['GET', 'POST'])
@login_required
def edit_post(id, page = 1):
    print notreal
    post = Post.query.get(id)
    if post == None:
        flash('Post not found.')
        return redirect(url_for('index'))
    if post.author.id != g.user.id:
        flash('You cannot edit this post.')
        return redirect(url_for('index'))
    form = PostForm()
    if form.validate_on_submit():
        language = guessLanguage(form.post.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''
        post.subject = form.subject.data
        post.body = form.post.data
        post.language = language
        db.session.add(post)
        db.session.commit()
        flash(gettext('Your post has been updated!'))
        return redirect(url_for('index'))
    elif request.method != "POST":
        form.subject.data = post.subject
        form.post.data = post.body
    comments = post.comments.order_by(Comment.timestamp.desc()).paginate(page, POSTS_PER_PAGE, False)
    return render_template('edit_post.html',
        post = post,
        form = form,
        comments = comments)

@app.route('/edit-comment/<int:id>', methods = ['GET', 'POST'])
@app.route('/edit-comment/<int:id>/<int:page>', methods = ['GET', 'POST'])
def edit_comment(id, page = 1):
    comment  = Comment.query.get(id)
    if comment == None:
        flash(gettext('Comment not found'))
        return redirect(url_for('index'))
    if comment.author.id != g.user.id:
        flash(gettext('You cannont edit this comment'))
        return redirect(url_for('index'))
    form = CommentForm()
    if form.validate_on_submit():
        language = guessLanguage(form.comment.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''
        comment.body = form.comment.data
        comment.language = language
        db.session.add(comment)
        db.session.commit()
        flash(gettext('Your comment has been updated!'))
        return redirect(url_for('post',id = comment.op.id,page = page))
    elif request.method != "POST":
        form.comment.data = comment.body
    return render_template('edit_comment.html',
        form = form) 

@app.route('/join-group/<int:group_id>')
@login_required
def join_group(group_id):
    if g.user.max_groups():
        flash(gettext('How many groups do you need to be in? Only 5 for you :)'))
        return redirect(url_for('index'))
    group = Group.query.get(group_id)
    if group == None:
        flash(gettext('Group was not found.'))
        return redirect(url_for('index'))
    add = group.add_user(g.user)
    if add is None:
        flash(gettext('You cannon join this group.'))
        return redirect(url_for('index'))
    db.session.add(add)
    db.session.commit()
    flash(gettext('Welcome to your new group!'))
    return redirect(url_for('group', group_id = group.id))

@app.route('/request-join-group/<int:group_id>')
@login_required
def request_join_group(group_id):
    if g.user.max_groups():
        flash(gettext('How many groups do you need to be in? Only 5 for you :)'))
        return redirect(url_for('index'))
    group = Group.query.get(group_id)
    if group == None:
        flash(gettext('Group was not found.'))
        return redirect(url_for('index'))
    if group.public:
        flash(gettext('This is a public group.'))
        return redirect(url_for('group', group_id = group.id))
    request = group.add_request(g.user)
    if request is None:
        flash(gettext('You cannon request to join this group.'))
        return redirect(url_for('index'))
    db.session.add(request)
    db.session.commit()
    flash(gettext('Your request has been submitted'))
    return redirect(url_for('group', group_id = group.id))

@app.route('/follow/<nickname>')
@login_required
def follow(nickname):
    user = User.query.filter_by(nickname = nickname).first()
    if user == None:
        flash('User ' + nickname + ' not found.')
        return redirect(url_for('index'))
    if user == g.user:
        flash(gettext('You can\'t follow yourself!'))
        return redirect(url_for('user', nickname = nickname))
    u = g.user.follow(user)
    if u is None:
        flash(gettext('Cannot follow %(nickname)s.', nickname = nickname))
        return redirect(url_for('user', nickname = nickname))
    db.session.add(u)
    db.session.commit()
    flash(gettext('You are now following %(nickname)s!', nickname = nickname))
    follower_notification(user, g.user)
    return redirect(url_for('user', nickname = nickname))

@app.route('/unfollow/<nickname>')
@login_required
def unfollow(nickname):
    user = User.query.filter_by(nickname = nickname).first()
    if user == None:
        flash('User ' + nickname + ' not found.')
        return redirect(url_for('index'))
    if user == g.user:
        flash(gettext('You can\'t unfollow yourself!'))
        return redirect(url_for('user', nickname = nickname))
    u = g.user.unfollow(user)
    if u is None:
        flash(gettext('Cannot unfollow %(nickname)s.', nickname = nickname))
        return redirect(url_for('user', nickname = nickname))
    db.session.add(u)
    db.session.commit()
    flash(gettext('You have stopped following %(nickname)s.', nickname = nickname))
    return redirect(url_for('user', nickname = nickname))

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    post = Post.query.get(id)
    if post == None:
        flash('Post not found.')
        return redirect(url_for('index'))
    if post.author.id != g.user.id:
        flash('You cannot delete this post.')
        return redirect(url_for('index'))
    # Delete group associations
    for group in post.groups.all():
        post.groups.remove(group)
    # Delete all comments.
    for comment in post.comments.all():
        db.session.delete(comment)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted.')
    return redirect(url_for('index'))
    
@app.route('/delete-comment/<int:id>')
@login_required
def delete_comment(id):
    comment = Comment.query.get(id)
    if comment == None:
        flash('Comment not found.')
        return redirect(url_for('index'))
    if comment.author.id != g.user.id:
        flash('You cannot delete this comment.')
        return redirect(url_for('index'))
    post = comment.op # Get post before comment is deleted. For redirect.
    db.session.delete(comment)
    db.session.commit()
    flash('Your comment has been deleted.')
    return redirect(url_for('post', id = post.id))

@app.route('/search', methods = ['GET', 'POST'])
@login_required
def search():
    if not g.search_enabled:
        flash(gettext('Search is not enabled.'))
        return redirect(url_for('index'))
    if g.search_form.validate_on_submit():
        return redirect(url_for('search_results',
            query = g.search_form.search.data,
            query_type = g.search_form.search_type.data))
    return render_template('advanced_search.html')

@app.route('/search_results/<query_type>/<query>')
@login_required
def search_results(query, query_type):
    if not g.search_enabled:
        flash(gettext('Search is not enabled.'))
        return redirect(url_for('index'))
    if query_type == 'User':
        results = User.query.whoosh_search('%s* OR *%s* OR *%s' % (query, query, query), MAX_SEARCH_RESULTS).all()
        return render_template('user_search.html',
            query = query,
            users = results)
    elif query_type == 'Post':
        results = Post.query.whoosh_search(query, MAX_SEARCH_RESULTS).all()
        return render_template('search_results.html',
            query = query,
            results = results)
    elif query_type == 'Group':
        results = Group.query.whoosh_search('%s* OR *%s* OR *%s' % (query, query, query), MAX_SEARCH_RESULTS).all()
        return render_template('group_search.html',
            query = query,
            results = results)
    else:
        return redirect(url_for('index'))

@app.route('/post/<int:id>', methods = ['GET', 'POST'])
@app.route('/post/<int:id>/<int:page>', methods = ['GET', 'POST'])
@login_required
def post(id, page = 1):
    post = Post.query.get(id)
    if post == None:
        flash("Post not found")
        return redirect(url_for('index'))
    form = CommentForm()
    if form.validate_on_submit():
        language = guessLanguage(form.comment.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''
        comment = Comment(body = form.comment.data,
            timestamp = datetime.utcnow(),
            author = g.user,
            op = post,
            language = language)
        db.session.add(comment)
        db.session.commit()
        flash(gettext('Your comment was added!'))
        return redirect(url_for('post', id = post.id))
    comments = post.comments.order_by(Comment.timestamp.desc()).paginate(page, POSTS_PER_PAGE, False)
    return render_template('post_comments.html',
        post = post,
        form = form,
        comments = comments)

@app.route('/answer/<int:id>', methods = ['GET', 'POST'])
@login_required
def answer(id):
    post = Post.query.get(id)
    if post == None:
        flash("Post not found")
        return redirect(url_for('index'))
    if post.author.id != g.user.id:
        flash("You cannot edit this post")
        return redirect(url_for('index'))
    form = AnswerForm()
    if form.validate_on_submit():
        post.answered = True
        post.answer = form.answer.data
        post.answer_time = datetime.utcnow()
        db.session.add(post)
        db.session.commit()
        flash(gettext('Your answer was added!'))
        return redirect(url_for('post', id = post.id))
    form.answer.data = post.answer
    return render_template('answer_post.html',
        post = post,
        form = form)

@app.route('/unanswered/<int:id>', methods = ['GET', 'POST'])
@login_required
def unanswered(id):
    post = Post.query.get(id)
    if post == None:
        flash("Post not found")
        return redirect(url_for('index'))
    if post.author.id != g.user.id:
        flash("You cannot edit this post")
        return redirect(url_for('index'))
    post.answered = False
    db.session.add(post)
    db.session.commit()
    flash(gettext('Your post has been marked as unanswered.'))
    return redirect(url_for('post', id = post.id))

@app.route('/translate', methods = ['POST'])
@login_required
def translate():
    return jsonify({
        'text': microsoft_translate(
            request.form['text'],
            request.form['sourceLang'],
            request.form['destLang']) })

