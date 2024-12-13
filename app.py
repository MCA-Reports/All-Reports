from flask import Flask, render_template, request, redirect, url_for, session, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from xhtml2pdf import pisa


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
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    mobile_no = db.Column(db.String(15), nullable=False)
    branch_name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    standard = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  
   

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

class Branch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Standard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

# Home route
@app.route('/')
def home():
    """Render the homepage."""
    return render_template('home.html')

# Personal Report Routes
@app.route('/personal/register', methods=['GET', 'POST'])
def P_register():
    """Handle registration for Personal Reports."""
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        mobile_no = request.form.get('mobile_no')
        branch_name = request.form.get('branch_name')
        username = request.form.get('username')
        standard = request.form.get('standard')
        password = request.form.get('password')

        # Define valid branches and standards
        valid_branches = [
            "Central", "NRW", "Berlin", "Hessen", "Bremen", 
            "Hamburg", "Greater Germany", "Bravaria", "Women"
        ]
        valid_standards = ["Member", "Worker", "Supporter"]

        # Validate dropdown values
        if branch_name not in valid_branches:
            return render_template('personal/register.html', error="Invalid Branch Name. Please select a valid option.")
        if standard not in valid_standards:
            return render_template('personal/register.html', error="Invalid Standard. Please select a valid option.")

        # Check if username or email already exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return render_template('personal/register.html', error="Username or Email already exists.")

        # Hash password and save user to database
        hashed_password = generate_password_hash(password)
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            mobile_no=mobile_no,
            branch_name=branch_name,
            username=username,
            standard=standard,
            password=hashed_password,
            role='personal'
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))

    # Render the registration form
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
            return redirect(url_for('personal_dashboard'))
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

@app.route('/personal/summary/pdf', methods=['GET'])
def P_summary_pdf():
    if 'user_id' not in session or session.get('role') != 'personal':
        return redirect(url_for('P_login'))
    
    user_id = session['user_id']
    reports = Report.query.filter_by(user_id=user_id).all()
    
    # Render the HTML template for the PDF
    rendered = render_template('personal/summary_pdf.html', reports=reports)
    
    # Convert HTML to PDF
    pdf = pisa.CreatePDF(rendered, dest=open('summary.pdf', 'wb'))
    
    # Serve the PDF as a downloadable response
    response = Response(open('summary.pdf', 'rb'), content_type='application/pdf')
    response.headers['Content-Disposition'] = 'inline; filename=personal_summary.pdf'
    return response

@app.route('/personal/dashboard', methods=['GET'])
def personal_dashboard():
    """Render the Personal Dashboard."""
    if 'user_id' not in session or session.get('role') != 'personal':
        return redirect(url_for('P_login'))
    return render_template('personal/dashboard.html')

# Branch Report Routes
@app.route('/branch/register', methods=['GET', 'POST'])
def B_register():
    """Handle registration for Branch Reports."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            return "Username already exists", 400
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role='branch')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('branch/register.html')


@app.route('/branch/login', methods=['GET', 'POST'])
def B_login():
    """Handle login for Branch Reports."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, role='branch').first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('home'))  # Redirect to branch-specific page if needed
        else:
            return "Invalid credentials", 401
    return render_template('branch/login.html')

# Secretariate Report Routes
@app.route('/secretariate/register', methods=['GET', 'POST'])
def S_register():
    """Handle registration for Secretariate Reports."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            return "Username already exists", 400
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role='secretariate')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('secretariate/register.html')


@app.route('/secretariate/login', methods=['GET', 'POST'])
def S_login():
    """Handle login for Secretariate Reports."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, role='secretariate').first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('home'))  # Redirect to secretariate-specific page if needed
        else:
            return "Invalid credentials", 401
    return render_template('secretariate/login.html')

# Logout Route
@app.route('/logout')
def logout():
    """Log out the user."""
    session.clear()
    return redirect(url_for('home'))

# Initialize the database
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the database tables based on your models
    app.run(debug=True)
