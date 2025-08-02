from flask import Flask, request, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://quickuser:sujal@localhost/quickdesk'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Login setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='user')

    tickets = db.relationship('Ticket', back_populates='user')

# Ticket Model
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', back_populates='tickets')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 6
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', 'all')
    sort_by = request.args.get('sort', 'recent')

    query = Ticket.query.filter_by(user_id=current_user.id)

    if search_query:
        query = query.filter(
            Ticket.subject.ilike(f"%{search_query}%") |
            Ticket.description.ilike(f"%{search_query}%")
        )

    if status_filter != 'all':
        query = query.filter_by(status=status_filter)

    if sort_by == 'recent':
        query = query.order_by(Ticket.id.desc())
    elif sort_by == 'oldest':
        query = query.order_by(Ticket.id.asc())

    pagination = query.paginate(page=page, per_page=per_page)
    tickets = pagination.items

    return render_template(
        'dashboard.html',
        tickets=tickets,
        total_tickets=query.count(),
        total_pages=pagination.pages,
        current_page=page,
        has_next=pagination.has_next,
        has_prev=pagination.has_prev,
        search_query=search_query,
        status_filter=status_filter,
        sort_by=sort_by
    )

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or Email already exists!')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registered successfully. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
        return redirect(url_for('login'))

    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Create Ticket
@app.route('/create-ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        subject = request.form['subject']
        description = request.form['description']
        ticket = Ticket(subject=subject, description=description, user_id=current_user.id)
        db.session.add(ticket)
        db.session.commit()
        flash('Ticket created successfully.')
        return redirect(url_for('dashboard'))

    return render_template('create_ticket.html')

# View Ticket Details
@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    return render_template('ticket_detail.html', ticket=ticket)

# Vote on Ticket
@app.route('/ticket/<int:ticket_id>/vote', methods=['POST'])
@login_required
def vote_ticket(ticket_id):
    # Example: print a message or update a vote count in DB
    print(f"User {current_user.username} voted on ticket {ticket_id}")
    
    # You can later implement logic here like updating vote count in DB

    # Redirect back to the ticket detail page
    return redirect(url_for('view_ticket', ticket_id=ticket_id))



# Update Ticket Status
@app.route('/ticket/<int:id>/update', methods=['POST'])
@login_required
def update_ticket(id):
    ticket = Ticket.query.get_or_404(id)
    if current_user.role == 'admin' or ticket.user_id == current_user.id:
        new_status = request.form.get('status')
        ticket.status = new_status
        db.session.commit()
        flash('Ticket status updated.')
    else:
        abort(403)
    return redirect(url_for('dashboard'))

# Main
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
