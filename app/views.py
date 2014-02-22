from flask import render_template, flash, redirect, session, url_for, request, g, jsonify
from flask.ext.login import login_user, logout_user, current_user, login_required
from flask.ext.sqlalchemy import get_debug_queries
from flask.ext.babel import gettext
from app import app, db, lm, oid, babel
from forms import LoginForm, EditForm, PostForm, SearchForm, CommentForm, AnswerForm
from models import User, ROLE_USER, ROLE_ADMIN, Post, Comment
from datetime import datetime
from emails import follower_notification
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
@login_required
def index(page = 1):
    form = PostForm()
    if form.validate_on_submit():
        language = guessLanguage(form.post.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''
        post = Post(subject = form.subject.data,
            body = form.post.data,
            timestamp = datetime.utcnow(),
            author = g.user,
            language = language)
        db.session.add(post)
        db.session.commit()
        flash(gettext('Your post is now live!'))
        return redirect(url_for('index'))
    posts = g.user.followed_posts().paginate(page, POSTS_PER_PAGE, False)
    return render_template('index.html',
        title = 'Home',
        form = form,
        posts = posts)

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
    posts = user.posts.paginate(page, POSTS_PER_PAGE, False)
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
    comments = post.comments.all()
    # Delete all comments if they exist.
    if comments:
        for comment in comments:
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
    db.session.delete(comment)
    db.session.commit()
    flash('Your comment has been deleted.')
    return redirect(request.args.get('next') or url_for('index'))

@app.route('/search', methods = ['POST'])
@login_required
def search():
    # If search type is not defined default to Post, For nav bar.
    g.search_form.search_type.data = g.search_form.search_type.data
    if g.search_form.search_type.data == "None":
        g.search_form.search_type.data = 'Post'
    query = g.search_form.search.data
    if not g.search_form.validate_on_submit():
        return redirect(url_for('index'))
    if g.search_form.search_type.data == 'User':
        results = User.query.whoosh_search('%s* OR *%s* OR *%s' % (query, query, query), MAX_SEARCH_RESULTS).all()
        return render_template('user_search.html',
            users = results)
    elif g.search_form.search_type.data == 'Post':
        results = Post.query.whoosh_search(query, MAX_SEARCH_RESULTS).all()
        return render_template('search_results.html',
            query = query,
            results = results)
    else:
        return redirect(url_for('index'))


   # return redirect(url_for('search_results', query_type = g.search_form.search_type.data, query = g.search_form.search.data))

@app.route('/search_results/<query_type>/<query>')
@login_required
def search_results(query, query_type = 'Post'):
    if query_type == 'User':
        results = User.query.whoosh_search('%s* OR *%s* OR *%s' % (query, query, query), MAX_SEARCH_RESULTS).all()
        return render_template('user_search.html',
            users = results)
    elif query_type == 'Post':
        results = Post.query.whoosh_search(query, MAX_SEARCH_RESULTS).all()
        return render_template('search_results.html',
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

