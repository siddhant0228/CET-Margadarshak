import re
import os
import json
from datetime import datetime, timedelta

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Length, Email
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import OperationalError

import pandas as pd

load_dotenv()

app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI") or "sqlite:///college_finder.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or "dev-secret-key"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True

db = SQLAlchemy(app)
Session(app)

DISTRICT_MAP = {}
json_path = os.path.join(app.root_path, "static", "districts.json")
if os.path.exists(json_path):
    try:
        with open(json_path, "r", encoding="utf8") as f:
            DISTRICT_MAP = json.load(f)
    except Exception as e:
        app.logger.warning("Failed to load static/districts.json: %s", e)
        DISTRICT_MAP = {}

if not DISTRICT_MAP:
    DISTRICT_MAP = {
        "Maharashtra": ["Mumbai City", "Mumbai Suburban", "Pune", "Nagpur", "Nashik", "Thane", "Kolhapur"],
        "Gujarat": ["Ahmedabad", "Vadodara", "Surat", "Rajkot"],
        "Goa": ["North Goa", "South Goa"],
        "Chhattisgarh": ["Raipur", "Bilaspur", "Durg"]
    }

def validate_input(data, required_fields):
    errors = []
    for field in required_fields:
        if not data.get(field):
            errors.append(f"{field.replace('_',' ').title()} is required")
    return errors

class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=1, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(min=7, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    name = StringField('Fullname', validators=[DataRequired()])
    phone_number = StringField('Phone number', validators=[DataRequired(), Length(min=7, max=20)])
    dob = DateField('Date Of Birth', validators=[DataRequired()], format='%Y-%m-%d')

    gender = SelectField('Gender', choices=[
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other')
    ])

    category = SelectField('Category', choices=[
        ('OPEN', 'Open'),
        ('OBC', 'OBC'),
        ('SC', 'SC'),
        ('ST', 'ST'),
        ('NT1', 'NT1'),
        ('NT2', 'NT2'),
        ('NT3', 'NT3'),
        ('EWS', 'EWS')
    ])

    home_state = SelectField('Home State', choices=[])
    district = SelectField('District', choices=[])
    percentile = StringField('Percentile', validators=[DataRequired()])
    submit = SubmitField('Profile')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    dob = db.Column(db.Date, nullable=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    gender = db.Column(db.String(10), nullable=True)
    category = db.Column(db.String(15), nullable=True)
    home_state = db.Column(db.String(100), nullable=True)
    district = db.Column(db.String(100), nullable=True)
    percentile = db.Column(db.Float, nullable=True)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

class College(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(100), nullable=True)
    category = db.Column(db.String(50), nullable=True)
    cutoff = db.Column(db.Float, nullable=True)

class Branch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20))
    name = db.Column(db.String(200), nullable=False)

class Cutoff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    round = db.Column(db.Integer, nullable=False)
    allocation_type = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    merit_number = db.Column(db.Integer, nullable=True)
    percentile = db.Column(db.Float, nullable=True)

    college_id = db.Column(db.Integer, db.ForeignKey('college.id'), nullable=False)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)

    college = db.relationship("College", backref="cutoffs")
    branch = db.relationship("Branch", backref="cutoffs")

class Placement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    percentage = db.Column(db.Float, nullable=False)
    college_id = db.Column(db.Integer, db.ForeignKey('college.id'), nullable=False)
    college = db.relationship("College", backref="placement")

class CollegeBranch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    round = db.Column(db.Integer, nullable=True)
    college_id = db.Column(db.Integer, db.ForeignKey('college.id'), nullable=False)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    college = db.relationship("College", backref="college_branches")
    branch = db.relationship("Branch", backref="college_branches")

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.permanent = True
    if session.get('user_id'):
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        password = form.password.data

        errors = validate_input({'email': email, 'password': password}, ['email', 'password'])
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("login.html", form=form)

        try:
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, password):
                session["user_id"] = user.id
                session["email"] = user.email
                session["username"] = user.name
                flash(f"Welcome back, {user.name}", "success")
                return redirect(url_for("profile"))
            else:
                flash("Invalid username or password", "danger")
        except OperationalError:
            flash("Our database is temporarily unavailable. Please try again.", "warning")
            return redirect(url_for('login'))
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data.strip()
        email = form.email.data.strip()
        phone_number = form.phone_number.data.strip()
        password = form.password.data

        errors = validate_input({'email': email, 'phone_number': phone_number, 'password': password},
                                ['email', 'phone_number', 'password'])

        try:
            if User.query.filter_by(email=email).first():
                errors.append("Email already used")
            if User.query.filter_by(phone_number=phone_number).first():
                errors.append("Phone number already used")
        except OperationalError:
            flash("Our database is temporarily unavailable. Please try again.", "warning")
            return redirect(url_for('register'))

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("register.html", form=form)

        try:
            hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
            new_user = User(name=name, email=email, phone_number=phone_number, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            session["user_id"] = new_user.id
            session["email"] = new_user.email
            session["username"] = new_user.name
            flash("Registered successfully", "success")
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {str(e)}", "danger")
            return render_template("register.html", form=form)
    return render_template("register.html", form=form)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    user = User.query.get(session.get('user_id'))
    form = ProfileForm(obj=user)

    state_choices = [(s, s) for s in sorted(DISTRICT_MAP.keys())]
    form.home_state.choices = [('', 'Select state')] + state_choices

    selected_state = None
    if request.method == 'POST':
        selected_state = request.form.get('home_state') or (user.home_state if user else None)
    else:
        selected_state = user.home_state if user and user.home_state else None

    if selected_state and selected_state in DISTRICT_MAP:
        form.district.choices = [('', 'Select district')] + [(d, d) for d in DISTRICT_MAP[selected_state]]
    else:
        form.district.choices = [('', 'Select a state first')]

    if request.method == 'POST':
        form.district.data = request.form.get('district', '')

    if form.validate_on_submit():
        try:
            user.name = form.name.data.strip()
            user.phone_number = form.phone_number.data.strip()
            user.dob = form.dob.data
            user.gender = form.gender.data.strip()
            user.category = form.category.data.strip()
            user.home_state = form.home_state.data.strip()
            user.district = form.district.data.strip()
            try:
                user.percentile = float(form.percentile.data)
            except Exception:
                user.percentile = None
            db.session.commit()
            flash("Profile updated", "success")

            action = request.form.get('action', 'save')
            if action == 'next':
                return redirect(url_for('preferences'))
            else:
                return redirect(url_for('profile'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error updating profile: {e}", "danger")

    return render_template("profile.html", form=form, user=user)

@app.route('/api/colleges')
def api_colleges():
    q = request.args.get('q', '').strip()
    limit = int(request.args.get('limit', 10))
    try:
        if not q:
            cols = College.query.order_by(College.name.asc()).limit(limit).all()
        else:
            pattern = f"%{q}%"
            cols = College.query.filter(College.name.ilike(pattern)).order_by(College.name.asc()).limit(limit).all()
    except Exception:
        cols = []
    results = [{"id": c.id, "name": c.name} for c in cols]
    return jsonify(results)

@app.route('/api/branches')
def api_branches():
    q = request.args.get('q', '').strip()
    limit = int(request.args.get('limit', 10))
    try:
        if not q:
            brs = Branch.query.order_by(Branch.name.asc()).all()
        else:
            pattern = f"%{q}%"
            brs = Branch.query.filter(Branch.name.ilike(pattern)).order_by(Branch.name.asc()).all()
    except Exception:
        brs = []

    unique = {}
    for b in brs:
        key = (b.name or "").strip().lower()
        if not key:
            continue
        if key not in unique:
            unique[key] = {"id": b.id, "name": b.name}

    results = list(unique.values())[:limit]
    return jsonify(results)

@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    if not session.get('user_id'):
        flash("Please login to set preferences.", "info")
        return redirect(url_for('login'))

    if request.method == 'POST':
        pc = request.form.get('preferred_colleges', '').strip()
        pb = request.form.get('preferred_branches', '').strip()

        preferred_colleges = [s.strip() for s in pc.split(',') if s.strip()] if pc else []
        preferred_branches = [s.strip() for s in pb.split(',') if s.strip()] if pb else []

        preferred_colleges = preferred_colleges[:10]
        preferred_branches = preferred_branches[:10]

        session['preferred_colleges'] = preferred_colleges
        session['preferred_branches'] = preferred_branches

        flash("Preferences saved. Generating recommendations...", "success")
        return redirect(url_for('recommend'))

    existing_colleges = session.get('preferred_colleges', [])
    existing_branches = session.get('preferred_branches', [])
    return render_template('preferences.html',
                           preferred_colleges=existing_colleges,
                           preferred_branches=existing_branches)

@app.route('/recommend', methods=['GET'])
def recommend():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please login to view recommendations.", "info")
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    preferred_colleges = session.get('preferred_colleges', [])
    preferred_branches = session.get('preferred_branches', [])

    try:
        all_rounds = []
        for r in [1, 2, 3]:
            path = f"data/pivot_gopens_cap{r}.csv"
            if os.path.exists(path):
                df = pd.read_csv(path)
                df.columns = df.columns.str.strip().str.title()
                rename_map = {
                    "Branch Name": "Branch",
                    "Percentile": "Cutoff",
                    "College Name": "College",
                    "Institute Code": "Institute Code",
                }
                df.rename(columns=rename_map, inplace=True)
                df = df.loc[:, ~df.columns.str.contains("^Unnamed", na=False)]
                df["round"] = r
                all_rounds.append(df)

        if not all_rounds:
            flash("Cutoff data files not found. Please upload CSVs in data/ directory.", "warning")
            return redirect(url_for('index'))

        cap_data = pd.concat(all_rounds, ignore_index=True)
    except Exception as e:
        flash(f"Error loading cutoff data: {e}", "danger")
        return redirect(url_for('index'))

    try:
        user_percentile = float(user.percentile or 0)
    except Exception:
        user_percentile = 0.0
    user_category = (user.category or "OPEN").strip().upper()

    expected_cols = {'College', 'Branch', 'Category', 'Cutoff'}
    if not expected_cols.issubset(set(cap_data.columns)):
        lower_map = {c.lower(): c for c in cap_data.columns}
        if 'college' in lower_map and 'College' not in cap_data.columns:
            cap_data['College'] = cap_data[lower_map['college']]
        if 'branch' in lower_map and 'Branch' not in cap_data.columns:
            cap_data['Branch'] = cap_data[lower_map['branch']]
        if 'category' in lower_map and 'Category' not in cap_data.columns:
            cap_data['Category'] = cap_data[lower_map['category']]
        if 'cutoff' in lower_map and 'Cutoff' not in cap_data.columns:
            cap_data['Cutoff'] = cap_data[lower_map['cutoff']]

    if not expected_cols.issubset(set(cap_data.columns)):
        flash("Cutoff CSV headers must include: 'College', 'Branch', 'Category', 'Cutoff'.", "danger")
        return redirect(url_for('index'))

    cap_data['College'] = cap_data['College'].astype(str).str.strip()
    cap_data['Branch'] = cap_data['Branch'].astype(str).str.strip()
    cap_data['Category'] = cap_data['Category'].astype(str).str.strip()
    cap_data['Cutoff'] = pd.to_numeric(cap_data['Cutoff'], errors='coerce')

    cap_data['Category_norm'] = cap_data['Category'].astype(str).str.upper().str.strip()
    cap_data['College_norm'] = cap_data['College'].astype(str).str.lower().str.strip()
    cap_data['Branch_norm'] = cap_data['Branch'].astype(str).str.lower().str.strip()

    user_category_norm = user_category

    df_filtered = cap_data[cap_data['Category_norm'].str.contains(re.escape(user_category_norm), na=False)].copy()

    if df_filtered.shape[0] == 0:
        df_filtered = cap_data.copy()
        flash("No cutoff rows matched your category exactly — showing results across all categories.", "warning")

    def compute_status(cutoff_val, user_pct):
        try:
            cutoff_val = float(cutoff_val)
        except Exception:
            return 'Unlikely'
        if user_pct >= cutoff_val + 2:
            return 'Safe'
        if cutoff_val - 2 <= user_pct < cutoff_val + 2:
            return 'Reach'
        return 'Unlikely'

    df_filtered['status'] = df_filtered['Cutoff'].apply(lambda x: compute_status(x, user_percentile))

    applied_college_filter = False
    applied_branch_filter = False
    df_pref = df_filtered

    if preferred_colleges:
        patterns = [re.escape(p).lower() for p in preferred_colleges if p]
        if patterns:
            pat = "|".join(patterns)
            df_pref = df_pref[df_pref['College_norm'].str.contains(pat, na=False)]
            applied_college_filter = True

    if preferred_branches:
        patterns_b = [re.escape(p).lower() for p in preferred_branches if p]
        if patterns_b:
            patb = "|".join(patterns_b)
            df_pref = df_pref[df_pref['Branch_norm'].str.contains(patb, na=False)]
            applied_branch_filter = True

    if df_pref.shape[0] == 0 and (applied_college_filter or applied_branch_filter):
        df_try_col = df_filtered
        df_try_branch = df_filtered
        if applied_college_filter:
            df_try_col = df_filtered[df_filtered['College_norm'].str.contains("|".join([re.escape(p).lower() for p in preferred_colleges]), na=False)]
        if applied_branch_filter:
            df_try_branch = df_filtered[df_filtered['Branch_norm'].str.contains("|".join([re.escape(p).lower() for p in preferred_branches]), na=False)]

        if df_try_col.shape[0] >= df_try_branch.shape[0] and df_try_col.shape[0] > 0:
            df_pref = df_try_col
            flash("Preferences applied loosely (college matches).", "info")
        elif df_try_branch.shape[0] > 0:
            df_pref = df_try_branch
            flash("Preferences applied loosely (branch matches).", "info")
        else:
            df_pref = df_filtered.copy()
            flash("Your preferred colleges/branches didn't match the dataset — showing recommendations without preference filters.", "warning")

    df_pref['Cutoff'] = df_pref['Cutoff'].fillna(-999)

    status_order = {'Safe': 0, 'Reach': 1, 'Unlikely': 2}
    df_pref['status_rank'] = df_pref['status'].map(status_order).fillna(3)
    recommendation_df = df_pref.sort_values(by=['status_rank', 'Cutoff'], ascending=[True, False]).head(200)

    recs = []
    for _, row in recommendation_df.iterrows():
        cutoff_val = row.get('Cutoff')
        recs.append({
            "college_name": row.get('College'),
            "branch_name": row.get('Branch'),
            "round": int(row.get('round')) if 'round' in row and not pd.isna(row.get('round')) else None,
            "cutoff": (float(cutoff_val) if cutoff_val != -999 else None),
            "status": row.get('status') or 'Unlikely'
        })

    if len(recs) == 0:
        app.logger.info("No recommendations generated. Sample categories: %s", cap_data['Category'].unique()[:20])
        app.logger.info("User: %s, category=%s, pct=%s, prefs=%s/%s", user.email, user_category, user_percentile, preferred_colleges, preferred_branches)

    return render_template('recommendation.html', recommendation=recs, user=user)

if __name__ == '__main__':
    app.run(debug=True)
