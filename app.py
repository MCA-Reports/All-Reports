from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for session management
app.secret_key = "your_secret_key"

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bmcag_reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # personal, branch, secretariate


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quran_ayat = db.Column(db.Integer, nullable=False)
    hadith_count = db.Column(db.Integer, nullable=False)
    islamic_literature = db.Column(db.String(255))
    prayers = db.Column(db.Integer, nullable=False)
    invitations = db.Column(db.Integer, nullable=False)
    invitation_materials = db.Column(db.Integer, nullable=False)
    books_distributed = db.Column(db.Integer, nullable=False)
    org_time_spent = db.Column(db.Integer, nullable=False)
    family_meetings = db.Column(db.Boolean, default=False)
    date_posted = db.Column(db.DateTime, default=db.func.current_timestamp())

# Routes
@app.route('/')
def home():
    """Render the homepage."""
    return render_template('home.html')


# Personal Report Routes
@app.route('/personal/register', methods=['GET', 'POST'])
def P_register():
    """Handle registration for Personal Reports."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            return "Username already exists", 400
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role='personal')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('personal/register.html')


@app.route('/personal/login', methods=['GET', 'POST'])
def P_login():
    """Handle login for Personal Reports."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, role='personal').first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('P_form'))  # Redirect to form page after login
        else:
            return "Invalid credentials", 401
    return render_template('personal/login.html')


@app.route('/personal/form', methods=['GET', 'POST'])
def P_form():
    """Render form for adding a new Personal Report."""
    if 'user_id' not in session or session.get('role') != 'personal':
        return redirect(url_for('P_login'))
    if request.method == 'POST':
        user_id = session['user_id']
        quran_ayat = request.form.get('quran_ayat')
        hadith_count = request.form.get('hadith_count')
        islamic_literature = request.form.get('islamic_literature')
        prayers = request.form.get('prayers')
        invitations = request.form.get('invitations')
        invitation_materials = request.form.get('invitation_materials')
        books_distributed = request.form.get('books_distributed')
        org_time_spent = request.form.get('org_time_spent')
        family_meetings = bool(request.form.get('family_meetings'))

        new_report = Report(
            user_id=user_id,
            quran_ayat=quran_ayat,
            hadith_count=hadith_count,
            islamic_literature=islamic_literature,
            prayers=prayers,
            invitations=invitations,
            invitation_materials=invitation_materials,
            books_distributed=books_distributed,
            org_time_spent=org_time_spent,
            family_meetings=family_meetings
        )
        db.session.add(new_report)
        db.session.commit()
        return redirect(url_for('P_summary'))
    return render_template('personal/form.html')


@app.route('/personal/summary', methods=['GET'])
def P_summary():
    """Render summary of Personal Reports."""
    if 'user_id' not in session or session.get('role') != 'personal':
        return redirect(url_for('P_login'))
    user_id = session['user_id']
    reports = Report.query.filter_by(user_id=user_id).all()
    return render_template('personal/summary.html', reports=reports)


@app.route('/logout')
def logout():
    """Log out the user."""
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the database tables based on your models
    app.run(debug=True)
