from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

# ====================
# Configuration
# ====================
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ====================
# Database Models
# ====================
class PersonalReportUser(UserMixin, db.Model):
    __tablename__ = 'personal_report_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class BranchReportUser(UserMixin, db.Model):
    __tablename__ = 'branch_report_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class P_Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    report_type = db.Column(db.String(20), nullable=False)  # 'personal', 'branch', or 'Secretariate'
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    quran_ayat = db.Column(db.Integer, nullable=False)
    hadith_count = db.Column(db.Integer, nullable=False)
    islamic_literature = db.Column(db.String(200), nullable=True)
    prayers = db.Column(db.Integer, nullable=False)
    invitations = db.Column(db.Integer, nullable=False)
    invitation_materials = db.Column(db.Integer, nullable=False)
    books_distributed = db.Column(db.Integer, nullable=False)
    org_time_spent = db.Column(db.Integer, nullable=False)
    completed_tasks = db.Column(db.Boolean, nullable=False)
    family_meetings = db.Column(db.Boolean, nullable=False)

# ====================
# Flask-Login Setup
# ====================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    report_type = session.get('report_type')
    if report_type == 'personal':
        return PersonalReportUser.query.get(int(user_id))
    elif report_type in ['branch', 'Secretariate']:
        return BranchReportUser.query.get(int(user_id))
    return None


# ====================
# Routes
# ====================
@app.route('/')
def home():
    return render_template('combined.html', section="home")


@app.route('/register/<report>', methods=['GET', 'POST'])
def register(report):
    if report not in ['personal', 'branch', 'Secretariate']:
        flash("Invalid report type!")
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        user_model = PersonalReportUser if report == 'personal' else BranchReportUser
        existing_user = user_model.query.filter_by(username=username).first()
        if existing_user:
            flash(f'Username already exists for {report.capitalize()} Report!')
            return redirect(url_for('register', report=report))

        new_user = user_model(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Registration successful for {report.capitalize()} Report!')
        return redirect(url_for('login', report=report))

    return render_template('combined.html', section="register", report=report)


@app.route('/login/<report>', methods=['GET', 'POST'])
def login(report):
    if report not in ['personal', 'branch', 'Secretariate']:
        flash("Invalid report type!")
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_model = PersonalReportUser if report == 'personal' else BranchReportUser
        user = user_model.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            session['report_type'] = report
            session['user_id'] = user.id

            # Redirect based on report type
            if report == 'personal':
                return redirect(url_for('form', report=report))
            elif report in ['branch', 'Secretariate']:
                return redirect(url_for('report_summary', report=report))
        else:
            flash('Invalid credentials!')
            return redirect(url_for('login', report=report))

    return render_template('combined.html', section="login", report=report)


@app.route('/P_summary/<report>')
@login_required
def report_summary(report):
    if report not in ['personal', 'branch', 'Secretariate']:
        flash("Invalid report type!")
        return redirect(url_for('home'))

    if session.get('report_type') != report:
        flash("Access denied!")
        logout_user()
        return redirect(url_for('login', report=report))

    user_id = session.get('user_id')
    reports = P_Report.query.filter_by(user_id=user_id, report_type=report).all()
    return render_template('combined.html', section="report_summary", report=report, reports=reports)


@app.route('/P_form/<report>', methods=['GET', 'POST'])
@login_required
def form(report):
    if report not in ['personal', 'branch', 'Secretariate']:
        flash("Invalid report type!")
        return redirect(url_for('home'))

    if session.get('report_type') != report:
        flash("Access denied!")
        logout_user()
        return redirect(url_for('login', report=report))

    if request.method == 'POST':
        data = request.form
        new_report = P_Report(
            user_id=session['user_id'],
            report_type=report,
            quran_ayat=int(data.get('quran_ayat', 0)),
            hadith_count=int(data.get('hadith_count', 0)),
            islamic_literature=data.get('islamic_literature', ''),
            prayers=int(data.get('prayers', 0)),
            invitations=int(data.get('invitations', 0)),
            invitation_materials=int(data.get('invitation_materials', 0)),
            books_distributed=int(data.get('books_distributed', 0)),
            org_time_spent=int(data.get('org_time_spent', 0)),
            completed_tasks=data.get('completed_tasks') == 'on',
            family_meetings=data.get('family_meetings') == 'on',
        )
        db.session.add(new_report)
        db.session.commit()
        flash('Report added successfully!')
        return redirect(url_for('report_summary', report=report))

    return render_template('combined.html', section="P_form", report=report)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('report_type', None)
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
