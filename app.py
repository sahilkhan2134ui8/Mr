from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, send
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    approved = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode('utf-8')
        new_user = User(username=username, password=password, approved=False)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration request sent! Wait for admin approval.", "info")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.approved:
                login_user(user)
                return redirect(url_for("chat"))
            else:
                flash("Your account is pending approval!", "warning")
        else:
            flash("Invalid credentials. Try again.", "danger")
    return render_template("login.html")

@app.route("/chat")
@login_required
def chat():
    return render_template("chat.html", username=current_user.username)

@socketio.on("message")
def handle_message(msg):
    send({"sender": current_user.username, "content": msg}, broadcast=True)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

# 🔥 Admin Panel (Protected with Password)
ADMIN_PASSWORD = "admin123"

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        password = request.form["password"]
        if password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Incorrect Password!", "danger")
    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin"))
    pending_users = User.query.filter_by(approved=False).all()
    return render_template("admin_dashboard.html", users=pending_users)

@app.route("/admin/approve/<int:user_id>")
def approve_user(user_id):
    if not session.get("admin"):
        return redirect(url_for("admin"))
    user = User.query.get(user_id)
    if user:
        user.approved = True
        db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/reject/<int:user_id>")
def reject_user(user_id):
    if not session.get("admin"):
        return redirect(url_for("admin"))
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for("admin_dashboard"))

if __name__ == "__main__":
    db.create_all()
    socketio.run(app, debug=True)
