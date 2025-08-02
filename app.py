from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import request, render_template
from werkzeug.security import generate_password_hash
from flask import redirect, url_for


app = Flask(__name__)

# PostgreSQL config
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://quickuser:sujal@localhost/quickdesk'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), default='user')
    tickets = db.relationship('Ticket', backref='user', lazy=True)

#ticket model
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# home route
@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'Username already exists!'

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

# login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # You can add real login logic here
        username = request.form['username']
        password = request.form['password']
        # Check credentials here...
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# for create schema in table
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

