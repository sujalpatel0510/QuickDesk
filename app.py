from flask import Flask, request, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

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
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    tickets = db.relationship('Ticket', back_populates='user', cascade='all, delete-orphan')
    comments = db.relationship('Comment', back_populates='user', cascade='all, delete-orphan')

# Ticket Model
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)

    user = db.relationship('User', back_populates='tickets')
    comments = db.relationship('Comment', back_populates='ticket', cascade='all, delete-orphan')

# Comment Model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)

    user = db.relationship('User', back_populates='comments')
    ticket = db.relationship('Ticket', back_populates='comments')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or Email already exists!', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registered successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        try:
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)
                flash('Logged in successfully.', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
        except ValueError:
            flash('Password format is invalid. Please reset your password.', 'danger')
            return redirect(url_for('login'))

        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 6
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', 'all')
    sort_by = request.args.get('sort', 'recent')

    query = Ticket.query

    if current_user.role != 'admin':
        query = query.filter_by(user_id=current_user.id)

    if search_query:
        query = query.filter(
            Ticket.subject.ilike(f"%{search_query}%") |
            Ticket.description.ilike(f"%{search_query}%")
        )

    if status_filter != 'all':
        query = query.filter_by(status=status_filter)

    if sort_by == 'recent':
        query = query.order_by(Ticket.created_at.desc())
    elif sort_by == 'oldest':
        query = query.order_by(Ticket.created_at.asc())

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

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    if not query:
        flash('Please enter a search term.', 'warning')
        return redirect(url_for('dashboard'))

    tickets_query = Ticket.query

    if current_user.role != 'admin':
        tickets_query = tickets_query.filter_by(user_id=current_user.id)

    tickets = tickets_query.filter(
        Ticket.subject.ilike(f'%{query}%') | Ticket.description.ilike(f'%{query}%')
    ).order_by(Ticket.created_at.desc()).all()

    return render_template('search_results.html', tickets=tickets, query=query)

@app.route('/create-ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        subject = request.form['subject'].strip()
        description = request.form['description'].strip()
        if not subject or not description:
            flash('Subject and description cannot be empty.', 'warning')
            return redirect(url_for('create_ticket'))

        ticket = Ticket(subject=subject, description=description, user_id=current_user.id)
        db.session.add(ticket)
        db.session.commit()
        flash('Ticket created successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_ticket.html')

@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.user_id != current_user.id and current_user.role != 'admin':
        abort(403)

    comments = Comment.query.filter_by(ticket_id=ticket_id).order_by(Comment.created_at.asc()).all()
    user_vote = None

    return render_template('ticket_detail.html', ticket=ticket, comments=comments, user_vote=user_vote)

@app.route('/ticket/<int:ticket_id>/add_comment', methods=['POST'])
@login_required
def add_comment(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.user_id != current_user.id and current_user.role != 'admin':
        abort(403)

    content = request.form.get('comment', '').strip()
    if not content:
        flash('Comment cannot be empty.', 'warning')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

    comment = Comment(content=content, user_id=current_user.id, ticket_id=ticket_id)
    db.session.add(comment)
    db.session.commit()
    flash('Comment added successfully.', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/ticket/<int:ticket_id>/vote', methods=['POST'])
@login_required
def vote_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    vote_type = request.form.get('vote_type') or request.form.get('vote')
    if vote_type == 'upvote':
        ticket.upvotes = (ticket.upvotes or 0) + 1
    elif vote_type == 'downvote':
        ticket.downvotes = (ticket.downvotes or 0) + 1
    else:
        flash('Invalid vote.', 'warning')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

    db.session.commit()
    flash('Your vote has been recorded.', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/ticket/<int:ticket_id>/update', methods=['POST'])
@login_required
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role == 'admin' or ticket.user_id == current_user.id:
        new_status = request.form.get('status')
        if new_status in ['Open', 'In Progress', 'Resolved', 'Closed']:
            ticket.status = new_status
            db.session.commit()
            flash('Ticket status updated.', 'success')
        else:
            flash('Invalid status value.', 'warning')
    else:
        abort(403)
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        try:
            if not bcrypt.check_password_hash(user.password, current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('profile'))
        except ValueError:
            flash('Password format is invalid. Please reset your password.', 'danger')
            return redirect(url_for('profile'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('profile'))

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        flash('Password updated successfully.', 'success')
        return redirect(url_for('profile'))

    total_tickets = Ticket.query.filter_by(user_id=user.id).count()
    open_tickets = Ticket.query.filter_by(user_id=user.id, status='Open').count()
    closed_tickets = Ticket.query.filter_by(user_id=user.id, status='Closed').count()

    user_data = (
        user.id,
        user.username,
        user.email,
        None,
        user.role,
        user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else 'N/A'
    )

    return render_template(
        'profile.html',
        user=user_data,
        total_tickets=total_tickets,
        open_tickets=open_tickets,
        closed_tickets=closed_tickets
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
