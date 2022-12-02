from flask import Flask, render_template, flash, redirect, url_for, abort, request, jsonify 
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt 
from flask_login import LoginManager, login_user, current_user, logout_user 
from flask_restful import Api, Resource 
import requests 

app = Flask(__name__) 
app.config["SECRET_KEY"] = "7eb3e04be57ddb87fa308c697b122b17" 
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db" 

bcrypt = Bcrypt(app) 
login_manager = LoginManager(app) 
db = SQLAlchemy()
db.init_app(app)

api = Api(app) 
from forms import LoginForm, RegistrationForm, AddBotForm 

@app.route('/') 
@app.route('/home') 
def home(): 
    if current_user.is_authenticated: 
        bots = Bot.query.all() 
        return render_template("home.html", bots=bots) 
    else: 
        return redirect(url_for("login")) 
    
@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated and current_user.group == "admin":
        form = RegistrationForm()
        if form.validate_on_submit() and not User.query.filter_by(username=form.username.data).first(): 
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode("UTF 8") 
            user = User(username=form.username.data, group=form.group.data, 
            password=hashed_password) 
            db.session.add(user) 
            db.session.commit() 
            flash(f"Added new {form.group.data} : {form.username.data}", "success") 
            redirect(url_for("admin")) 
        else:
            if request.method == "POST":  
                flash(f"Form not validated") 
                return render_template("register.html", title="Register", form=form) 
    else: 
        return abort(403) 

@app.route('/addbot', methods=["GET", "POST"]) 
def add_bot(): 
    if current_user.is_authenticated and current_user.group == "admin": 
        form = AddBotForm() 
        if form.validate_on_submit(): 
            bot = Bot(id=form.id.data, type=form.type.data) 
            db.session.add(bot) 
            db.session.commit() 
            flash(f"A new {form.type.data} bot was added") 
            return render_template("add_bot.html", title="Add a Bot", form=form) 
    else: 
        abort(403) 

@app.route('/login', methods=["GET", "POST"]) 
def login(): 
    if current_user.is_authenticated: 
        return redirect(url_for("home")) 
    form = LoginForm() 
    if request.method != "GET": 
        print("here here")
        user = User.query.filter_by(username=form.username.data).first() 
        print(user)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user,remember=True) 
        flash("Login Successful") 
        return redirect(url_for("home"))

    else: 

        flash("Login unsuccessful! Please check your username and password", "warning") 
        return render_template("login.html", title="Login", form=form) 
    
@app.route('/logout') 
def logout(): 
        logout_user() 
        return redirect(url_for("login"))

@app.route('/admin') 
def admin(): 
    if current_user.is_authenticated and current_user.group == "admin": 
        return render_template("admin.html", title="Administration")
    else: 
        return abort(403)

@app.route('/admin/users') 
def admin_users(): 
    if current_user.is_authenticated and current_user.group == "admin": 
        users = User.query.all() 
        return render_template("admin_users.html", users=users) 
    else: 
        return abort(403)

@app.route('/admin/bots') 
def admin_bots(): 
    if current_user.is_authenticated and current_user.group == "admin": 
        bots = Bot.query.all() 
        return render_template("admin_bots.html", bots=bots) 
    else: 
        return abort(403)

@app.route('/mover/<int:id>') 
def mover(id): 
    if current_user.is_authenticated: 
        return render_template("mover.html", id=id) 
    else: 
        return 403 

@app.route('/Forklift/<int:id>') 
def forklift(id): 
    if current_user.is_authenticated: 
        return render_template("forklift.html", id=id) 
    else: 
        return 403 
from flask_login import UserMixin 

@login_manager.user_loader 
def load_user(user_id): 
    return User.query.get(int(user_id))

class User(db.Model, UserMixin): 
    id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(20), unique=True, nullable=False) 
    group = db.Column(db.String(20), default="staff", nullable=False) 
    password = db.Column(db.String(60), nullable=False) 

    def __repr__(self): 
        return f"User('{self.username}')"

class Bot(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    type = db.Column(db.String, nullable=False) 
    socket = db.Column(db.String(50), unique=True)

    def __repr__(self): 
        return f"Bot : {self.id}"

class Control(Resource):
    
    def get(self): 
        return {"user": current_user.username}

    def post(self, botid, operation): 
        if operation == "forward": 
            ip = Bot.query.filter_by(id=botid).first().socket 
            requests.post(f"http://{ip}/forward") 
            return 200 
        if operation == "backward": 
            ip = Bot.query.filter_by(id=botid).first().socket 
            requests.post(f"http://{ip}/backward") 
            return 200 
        if operation == "right": 
            ip = Bot.query.filter_by(id=botid).first().socket 
            requests.post(f"http://{ip}/right") 
            return 200 
        if operation == "left": 
            ip = Bot.query.filter_by(id=botid).first().socket 
            requests.post(f"http://{ip}/left") 
            return 200 
        if operation == "up": 
            ip = Bot.query.filter_by(id=botid).first().socket 
            requests.post(f"http://{ip}/up") 
            return 200 
        if operation == "down": 
            ip = Bot.query.filter_by(id=botid).first().socket 
            requests.post(f"http://{ip}/down") 
            return 200

class Internal(Resource): 
    def post(self, botid, ip): 
        bot = Bot.query.filter_by(id=botid).first() 
        bot.socket = ip 
        db.session.commit() 
        return 200

api.add_resource(Control, '/api/<int:botid>/<string:operation>/') 
api.add_resource(Internal, '/api/botinit/<int:botid>/<string:ip>') 
with app.app_context(): 
    db.create_all()
if __name__ == '__main__': 
    app.debug = True
    app.run()