from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlite3 import IntegrityError, Error
from functools import wraps
from sqlalchemy.orm import relationship
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from forms import CreatePostForm, RegisterUserForm, LogInUserForm, CreateComment
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    # -- PARENT --
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # -         -
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("CommentPost", back_populates="comment_author")
    # ------------


class BlogPost(db.Model, UserMixin):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # -- CHILD --
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")
    # -----------

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # -- PARENT --
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("CommentPost", back_populates="parent_post")
    # ------------


class CommentPost(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # -- CHILD --
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")
    # -         -
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    # -----------

    text = db.Column(db.Text, nullable=False)


# db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() != "1":
            flash("Sign in as Administrator")
            return redirect(url_for('login', next=request.url))
        return func(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html.j2", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():
        password_hash_and_salted = generate_password_hash(password=request.form["password"],
                                                          method="pbkdf2:sha256", salt_length=8)
        new_user = User(name=request.form["name"], email=request.form["email"], password=password_hash_and_salted)
        db.session.add(new_user)
        try:
            db.session.commit()
        except Error or IntegrityError:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))
        else:
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html.j2", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LogInUserForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=request.form["email"]).first()
        try:
            if check_password_hash(user.password, request.form["password"]):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password Incorrect")
        except AttributeError:
            flash("Invalid Email. Try Again")
    return render_template("login.html.j2", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CreateComment()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = CommentPost(comment_author=current_user, parent_post=requested_post, text=form.comment.data)
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for('login', next=request.url))
    return render_template("post.html.j2", post=requested_post, current_user=current_user, form=form)


@app.route("/about")
def about():
    return render_template("about.html.j2", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html.j2", current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html.j2", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html.j2", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
    # app.run(host='0.0.0.0', port=5000)

# admin@email.com
# fds@f2s6df$ds2f)

# nallely@example.com
# l4d"(sGFf#KtD=Fdfs$
