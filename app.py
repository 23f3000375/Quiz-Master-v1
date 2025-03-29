from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, time, timedelta
import logging

# Logging configure krne ke liye
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz_master.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

## Models

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    full_name = db.Column(db.String(150))
    qualification = db.Column(db.String(100))
    dob = db.Column(db.Date)
    role = db.Column(db.String(50), default='user')

    scores = db.relationship('Score', backref='user', lazy=True)


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text)

    chapters = db.relationship('Chapter', backref='subject', lazy=True)


class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)

    quizzes = db.relationship('Quiz', backref='chapter', lazy=True)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    date_of_quiz = db.Column(db.Date, nullable=False)
    duration = db.Column(db.Time, nullable=False)
    remarks = db.Column(db.String, nullable=True)
   
    questions = db.relationship('Question', backref='quiz', lazy=True)
    scores = db.relationship('Score', backref='quiz', lazy=True)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_statement = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200), nullable=False)
    option4 = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False) 

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    total_score = db.Column(db.Integer)

@login_manager.user_loader
def load_current_user(user_id):
    return db.session.get(User, int(user_id))  # Fixed LegacyAPIWarning yha se 

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        try:
            uname = request.form.get('username')
            pwd = request.form.get('password')
            if not uname or not pwd:
                flash('Both username and password are required.', 'danger')
                return redirect(url_for('user_login'))
            user = User.query.filter_by(username=uname).first()
            if user and check_password_hash(user.password, pwd):
                login_user(user)
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))
            flash('Invalid credentials provided.', 'danger')
            return redirect(url_for('user_login'))
        except Exception as ex:
            print(f"Login error: {ex}")
            flash('An unexpected error occurred during login.', 'danger')
            return redirect(url_for('user_login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        try:
            uname = request.form.get('username')
            pwd = request.form.get('password')
            fname = request.form.get('full_name')
            qual = request.form.get('qualification')
            dob_input = request.form.get('dob')
            dob_parsed = datetime.strptime(dob_input, '%Y-%m-%d').date()
            if User.query.filter_by(username=uname).first():
                flash('Username already exists. Please choose another.', 'danger')
                return redirect(url_for('user_register'))
            hashed_pwd = generate_password_hash(pwd)
            new_user = User(username=uname, password=hashed_pwd,
                            full_name=fname, qualification=qual, dob=dob_parsed)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('user_login'))
        except ValueError:
            flash('Incorrect date format. Use YYYY-MM-DD.', 'danger')
            return redirect(url_for('user_register'))
        except Exception as ex:
            flash(f'Error during registration: {str(ex)}', 'danger')
            return redirect(url_for('user_register'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def user_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    all_subjects = Subject.query.all()
    for subj in all_subjects:
        for chap in subj.chapters:
            chap.num_questions = Question.query.join(Quiz).filter(Quiz.chapter_id == chap.id).count()
    return render_template('admin/admin_dashboard.html', subjects=all_subjects)

@app.route('/admin/quiz')
@login_required
def admin_quiz_view():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    quiz_entries = db.session.query(Quiz, Chapter, Subject) \
        .join(Chapter, Quiz.chapter_id == Chapter.id) \
        .join(Subject, Chapter.subject_id == Subject.id).all()
    
    formatted_quizzes = []
    for quiz, chapter, subject in quiz_entries:
        formatted_quizzes.append({
            'quiz': quiz,
            'chapter': chapter,
            'subject': subject,
            'num_questions': Question.query.filter_by(quiz_id=quiz.id).count()
        })
    return render_template('admin/quiz_management.html', quizzes=formatted_quizzes)

@app.route('/admin/summary')
@login_required
def admin_overview():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    top_scores = db.session.query(
        Subject.name, db.func.max(Score.total_score)
    ).join(Chapter, Chapter.subject_id == Subject.id) \
     .join(Quiz, Quiz.chapter_id == Chapter.id) \
     .join(Score, Score.quiz_id == Quiz.id) \
     .group_by(Subject.name).all()
    attempts = db.session.query(
        Subject.name, db.func.count(Score.id)
    ).join(Chapter, Chapter.subject_id == Subject.id) \
     .join(Quiz, Quiz.chapter_id == Chapter.id) \
     .join(Score, Score.quiz_id == Quiz.id) \
     .group_by(Subject.name).all()

    scores_chart = {
        "labels": [s[0] for s in top_scores],
        "values": [s[1] for s in top_scores]
    }
    attempts_chart = {
        "labels": [a[0] for a in attempts],
        "values": [a[1] for a in attempts]
    }
    return render_template('admin/admin_summary.html',
                           top_scores_data=scores_chart,
                           user_attempts_data=attempts_chart)

@app.route('/admin/subject/new', methods=['GET', 'POST'])
@login_required
def add_new_subject():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    if request.method == 'POST':
        subj_name = request.form.get('name')
        subj_desc = request.form.get('description')
        if not subj_name:
            flash('Subject name is required.', 'danger')
            return render_template('admin/new_subject.html')
        if Subject.query.filter_by(name=subj_name).first():
            flash('A subject with this name already exists.', 'danger')
            return render_template('admin/new_subject.html')
        try:
            new_subj = Subject(name=subj_name, description=subj_desc)
            db.session.add(new_subj)
            db.session.commit()
            flash('Subject added successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding subject: {str(e)}', 'danger')
            return render_template('admin/new_subject.html')
    return render_template('admin/new_subject.html')

@app.route('/admin/subject/edit/<int:subject_id>', methods=['GET', 'POST'])
@login_required
def modify_subject(subject_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    subj = Subject.query.get_or_404(subject_id)
    
    if request.method == 'POST':
        new_name = request.form.get('subject_name')
        new_description = request.form.get('subject_description')
        
        # Validation: Check krte hai agr name khaali hai to
        if not new_name:
            flash('Subject name is required.', 'danger')
            return render_template('admin/edit_subject.html', subject=subj)
        
        # Check krenge duplicate subject name ke liye
        existing_subject = Subject.query.filter(Subject.name == new_name, Subject.id != subject_id).first()
        if existing_subject:
            flash('A subject with this name already exists.', 'danger')
            return render_template('admin/edit_subject.html', subject=subj)
        
        # Subject details update krenge
        subj.name = new_name
        subj.description = new_description
        
        try:
            db.session.commit()
            flash('Subject updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as ex:
            db.session.rollback()
            flash(f'Error updating subject: {str(ex)}', 'danger')
            return render_template('admin/edit_subject.html', subject=subj)
    
    return render_template('admin/edit_subject.html', subject=subj)

@app.route('/admin/subject/delete/<int:subject_id>', methods=['POST'])
@login_required
def remove_subject(subject_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    subj = Subject.query.get_or_404(subject_id)
    try:
        for chap in subj.chapters:
            related_quizzes = Quiz.query.filter_by(chapter_id=chap.id).all()
            for quiz in related_quizzes:
                Question.query.filter_by(quiz_id=quiz.id).delete()
                db.session.delete(quiz)
            db.session.delete(chap)
        db.session.delete(subj)
        db.session.commit()
        flash('Subject deleted successfully.', 'success')
    except Exception as ex:
        db.session.rollback()
        flash(f'Error deleting subject: {ex}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/chapter/new/<int:subject_id>', methods=['GET'])
@login_required
def create_chapter_form(subject_id):
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('index'))
    subj = Subject.query.get_or_404(subject_id)
    return render_template('admin/add_chapter.html', subject=subj)

@app.route('/add_chapter/<int:subject_id>', methods=['POST'])
@login_required
def add_new_chapter(subject_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    subj = Subject.query.get_or_404(subject_id)
    chap_name = request.form.get('name')
    chap_desc = request.form.get('description')
    if not chap_name or not chap_desc:
        flash('Both chapter name and description are required.', 'danger')
        return redirect(url_for('admin_dashboard'))
    new_chap = Chapter(name=chap_name, description=chap_desc, subject_id=subj.id)
    try:
        db.session.add(new_chap)
        db.session.commit()
        flash(f'Chapter "{chap_name}" added to subject "{subj.name}".', 'success')
    except Exception as ex:
        db.session.rollback()
        flash(f'Error adding chapter: {ex}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/chapter/edit/<int:chapter_id>', methods=['GET', 'POST'])
@login_required
def modify_chapter(chapter_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    chap = Chapter.query.get_or_404(chapter_id)
    if request.method == 'POST':
        chap.name = request.form.get('name')
        chap.description = request.form.get('description')
        try:
            db.session.commit()
            flash('Chapter updated successfully.', 'success')
        except Exception as ex:
            db.session.rollback()
            flash(f'Error updating chapter: {ex}', 'danger')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/edit_chapter.html', chapter=chap)

@app.route('/admin/chapter/delete/<int:chapter_id>', methods=['POST'])
@login_required
def remove_chapter(chapter_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    chap = Chapter.query.get_or_404(chapter_id)
    try:
        related_quizzes = Quiz.query.filter_by(chapter_id=chap.id).all()
        for quiz in related_quizzes:
            Question.query.filter_by(quiz_id=quiz.id).delete()
            db.session.delete(quiz)
        db.session.delete(chap)
        db.session.commit()
        flash('Chapter deleted successfully.', 'success')
    except Exception as ex:
        db.session.rollback()
        flash(f'Error deleting chapter: {ex}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/quiz/new', methods=['GET', 'POST'])
@login_required
def add_quiz_entry():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    all_subjects = Subject.query.all()
    all_chapters = Chapter.query.all()
    if request.method == 'POST':
        try:
            q_title = request.form.get('quiz_title')
            chap_id = request.form.get('chapter_id')
            quiz_date_str = request.form.get('date')
            duration_str = request.form.get('duration')
            remarks_text = request.form.get('remarks') or None
            if not q_title or not chap_id or not duration_str or not quiz_date_str:
                flash("All quiz fields are mandatory.", "danger")
                return redirect(url_for('add_quiz_entry'))
            duration_obj = datetime.strptime(duration_str, '%H:%M').time()
            quiz_date_obj = datetime.strptime(quiz_date_str, '%Y-%m-%d').date()
            new_quiz = Quiz(title=q_title, chapter_id=int(chap_id),
                            date_of_quiz=quiz_date_obj, duration=duration_obj,
                            remarks=remarks_text)
            db.session.add(new_quiz)
            db.session.commit()
            flash('New quiz created successfully.', 'success')
            return redirect(url_for('admin_quiz_view'))
        except Exception as ex:
            db.session.rollback()
            flash(f'Error creating quiz: {ex}', 'danger')
    return render_template('admin/new_quiz.html', subjects=all_subjects, chapters=all_chapters)

@app.route('/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def modify_quiz(quiz_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    quiz_entry = Quiz.query.get_or_404(quiz_id)
    chapters_list = Chapter.query.all()
    if request.method == 'POST':
        if 'title' not in request.form:
            flash("Missing title in submission.", "danger")
            return redirect(url_for('modify_quiz', quiz_id=quiz_entry.id))
        quiz_entry.title = request.form.get('title', quiz_entry.title)
        dur_str = request.form.get('duration', "00:00")
        if len(dur_str) == 5:
            dur_str += ":00"
        try:
            quiz_entry.duration = datetime.strptime(dur_str, "%H:%M:%S").time()
        except ValueError:
            flash("Duration format error. Use HH:MM.", "danger")
            return redirect(url_for('modify_quiz', quiz_id=quiz_entry.id))
        quiz_entry.remarks = request.form.get('remarks', quiz_entry.remarks)
        db.session.commit()
        flash('Quiz updated successfully.', 'success')
        return redirect(url_for('admin_quiz_view'))
    return render_template('admin/edit_quiz.html', quiz=quiz_entry, chapters=chapters_list)

@app.route('/add_question/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def add_question(quiz_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    quiz = Quiz.query.get_or_404(quiz_id) 
    if request.method == 'POST':
        question_statement = request.form.get('question_statement')
        option1 = request.form.get('option1')
        option2 = request.form.get('option2')
        option3 = request.form.get('option3')
        option4 = request.form.get('option4')
        correct_option = request.form.get('correct_option')
        
        # Check krne ke liye ki saari fields present hai
        if not all([question_statement, option1, option2, option3, option4, correct_option]):
            flash('All fields are required.', 'danger')
            return render_template('admin/new_question.html', quiz_id=quiz_id)
        
        # Do options check krne ke liye. Agr ek se jyada option hai to save changes pe click krne pe automatically uss page ko reload krega ek warning ke saath
        options = [option1, option2, option3, option4]
        if len(options) != len(set(options)):
            flash('All options must be unique. Please provide distinct values for each option.', 'danger')
            return render_template('admin/new_question.html', quiz_id=quiz_id)
        
        if correct_option not in ['A', 'B', 'C', 'D']:
            flash('Invalid correct option selected.', 'danger')
            return render_template('admin/new_question.html', quiz_id=quiz_id)
        
        try:
            new_question = Question(
                quiz_id=quiz_id,
                question_statement=question_statement,
                option1=option1,
                option2=option2,
                option3=option3,
                option4=option4,
                correct_option=correct_option
            )
            db.session.add(new_question)
            db.session.commit()
            flash('Question added successfully.', 'success')
            return redirect(url_for('manage_questions', quiz_id=quiz_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding question: {str(e)}', 'danger')
    return render_template('admin/new_question.html', quiz_id=quiz_id, quiz=quiz)

@app.route('/manage_questions/<int:quiz_id>')
@login_required
def manage_questions(quiz_id):
    if current_user.role != 'admin':
        flash('Only admins can manage questions.', 'error')
        return redirect(url_for('index'))
    try:
        quiz_entry = Quiz.query.get_or_404(quiz_id)
        quiz_questions = Question.query.filter_by(quiz_id=quiz_id).all()
        return render_template('admin/manage_question.html', quiz=quiz_entry, questions=quiz_questions)
    except Exception as e:
        flash(f'Error loading questions: {str(e)}', 'danger')
        return redirect(url_for('admin_quiz_view'))

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
def edit_question(question_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    question = Question.query.get_or_404(question_id)
    quiz = Quiz.query.get_or_404(question.quiz_id)  
    if request.method == 'POST':
        question_statement = request.form.get('question_statement')
        option1 = request.form.get('option1')
        option2 = request.form.get('option2')
        option3 = request.form.get('option3')
        option4 = request.form.get('option4')
        correct_option = request.form.get('correct_option')
        
        if not all([question_statement, option1, option2, option3, option4, correct_option]):
            flash('All fields are required.', 'danger')
            return render_template('admin/edit_question.html', question=question, quiz=quiz)
        
        # Check for duplicate options
        options = [option1, option2, option3, option4]
        if len(options) != len(set(options)):
            flash('All options must be unique. Please provide distinct values for each option.', 'danger')
            return render_template('admin/edit_question.html', question=question, quiz=quiz)
        
        option_mapping = {'1': 'A', '2': 'B', '3': 'C', '4': 'D'}
        correct_option = option_mapping.get(correct_option, correct_option)
        if correct_option not in ['A', 'B', 'C', 'D']:
            flash('Invalid correct option selected.', 'danger')
            return render_template('admin/edit_question.html', question=question, quiz=quiz)
        
        try:
            question.question_statement = question_statement
            question.option1 = option1
            question.option2 = option2
            question.option3 = option3
            question.option4 = option4
            question.correct_option = correct_option
            db.session.commit()
            flash('Question updated successfully.', 'success')
            return redirect(url_for('manage_questions', quiz_id=quiz.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating question: {str(e)}', 'danger')
    
    # This return statement was missing for GET requests
    return render_template('admin/edit_question.html', question=question, quiz=quiz)

@app.route('/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    try:
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting question: {str(e)}', 'danger')
    return redirect(url_for('manage_questions', quiz_id=quiz_id))

@app.route('/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def remove_quiz(quiz_id):
    print(f"Attempting to delete quiz ID: {quiz_id} by user: {current_user.id}")
    if current_user.role != 'admin':
        print("User not admin, redirecting to index")
        return redirect(url_for('index'))
    quiz_entry = Quiz.query.get_or_404(quiz_id)
    try:
        Question.query.filter_by(quiz_id=quiz_id).delete()
        db.session.delete(quiz_entry)
        db.session.commit()
        flash('Quiz removed successfully.', 'success')
    except Exception as ex:
        db.session.rollback()
        flash(f'Error deleting quiz: {ex}', 'danger')
    return redirect(url_for('admin_quiz_view'))

@app.route('/admin/search', methods=['GET'])
@login_required
def search_admin():
    if current_user.role != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))
    term = request.args.get('search', '').strip()
    if not term:
        flash("Enter a search term.", "warning")
        return redirect(url_for('admin_dashboard'))
    users_found = User.query.filter(
        db.or_(User.full_name.ilike(f"%{term}%"), User.username.ilike(f"%{term}%"))
    ).all()
    subjects_found = Subject.query.filter(Subject.name.ilike(f"%{term}%")).all()
    chapters_found = Chapter.query.filter(Chapter.name.ilike(f"%{term}%")).all()
    quizzes_found = db.session.query(Quiz, Chapter, Subject) \
        .join(Chapter, Quiz.chapter_id == Chapter.id) \
        .join(Subject, Chapter.subject_id == Subject.id) \
        .filter(db.or_(
            Quiz.title.ilike(f"%{term}%"),  
            Quiz.remarks.ilike(f"%{term}%"),
            Chapter.name.ilike(f"%{term}%"),
            Subject.name.ilike(f"%{term}%")
        )) \
        .all()
    questions_found = db.session.query(Question, Quiz, Chapter, Subject) \
        .join(Quiz, Question.quiz_id == Quiz.id) \
        .join(Chapter, Quiz.chapter_id == Chapter.id) \
        .join(Subject, Chapter.subject_id == Subject.id) \
        .filter(db.or_(Question.question_statement.ilike(f"%{term}%"),
                       Question.option1.ilike(f"%{term}%"),
                       Question.option2.ilike(f"%{term}%"),
                       Question.option3.ilike(f"%{term}%"),
                       Question.option4.ilike(f"%{term}%"),
                       Subject.name.ilike(f"%{term}%"),
                       Chapter.name.ilike(f"%{term}%"))) \
        .all()
    return render_template('admin/admin_search.html',
                           search_query=term,
                           user_results=users_found,
                           subject_results=subjects_found,
                           chapter_results=chapters_found,
                           quiz_results=quizzes_found,
                           question_results=questions_found)

@app.route('/user/dashboard', methods=['GET'])
@login_required
def user_dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    search_term = request.args.get('search', '').strip()
    today = date.today()  
    quiz_query = db.session.query(
        Quiz.id.label('id'),
        db.func.count(Question.id).label('num_questions'),
        Quiz.date_of_quiz.label('date'),
        Quiz.duration.label('duration')
    ).outerjoin(Question, Question.quiz_id == Quiz.id) \
     .group_by(Quiz.id)
    if search_term:
        quiz_query = quiz_query.join(Chapter, Quiz.chapter_id == Chapter.id) \
            .join(Subject, Chapter.subject_id == Subject.id) \
            .filter(db.or_(Subject.name.ilike(f"%{search_term}%"),
                           Chapter.name.ilike(f"%{search_term}%"),
                           Quiz.date_of_quiz.ilike(f"%{search_term}%")))
    quizzes_list = quiz_query.all()
    formatted_quizzes = []
    for quiz in quizzes_list:
        duration_str = f"{quiz.duration.hour:02d}:{quiz.duration.minute:02d}" if quiz.duration else "00:00"
        formatted_quizzes.append({
            'id': quiz.id,
            'num_questions': quiz.num_questions,
            'date': quiz.date.strftime('%d/%m/%Y') if quiz.date else 'N/A',
            'duration': duration_str
        })
    return render_template('user/user_dashboard.html', quizzes=formatted_quizzes, user_name=current_user.full_name)

@app.route('/start_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def attempt_quiz(quiz_id):
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    quiz_item = Quiz.query.get_or_404(quiz_id)
    all_questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    if not all_questions:
        flash("No questions available for this quiz.", "warning")
        return redirect(url_for('user_dashboard'))

  
    if 'quiz_start_time' not in session or session.get('current_quiz_id') != quiz_id:
        try:
            total_seconds = quiz_item.duration.hour * 3600 + quiz_item.duration.minute * 60 + (quiz_item.duration.second if quiz_item.duration.second else 0)
            session['quiz_duration'] = total_seconds
            session['quiz_start_time'] = datetime.now().isoformat()
            session['current_quiz_id'] = quiz_id
            session['quiz_progress'] = {'current_question_index': 0, 'score': 0, 'answered_questions': {}}
        except AttributeError:
            flash('Invalid quiz duration. Please contact the admin.', 'danger')
            return redirect(url_for('user_dashboard'))

   # bacha hua samay calculate krne ke liye
    try:
        duration_sec = int(session.get('quiz_duration', 0))
        start_time = datetime.fromisoformat(session['quiz_start_time'])
        elapsed = int((datetime.now() - start_time).total_seconds())
        remaining = max(duration_sec - elapsed, 0)
    except Exception as ex:
        flash('Session error. Restart the quiz.', 'danger')
        return redirect(url_for('user_dashboard'))

    if remaining <= 0:
        flash("Time's up! Quiz submitted automatically.", "danger")
        # score save krte hai redirect krne se pahle
        progress = session.get('quiz_progress', {})
        score = int(progress.get('score', 0))  
        new_score = Score(
            quiz_id=quiz_id,
            user_id=current_user.id,
            total_score=score
        )
        db.session.add(new_score)
        db.session.commit()
        session.pop('quiz_progress', None)
        session.pop('current_quiz_id', None)
        session.pop('quiz_start_time', None)
        session.pop('quiz_duration', None)
        return redirect(url_for('user_dashboard'))

    progress = session.get('quiz_progress', {})

    current_idx = int(progress.get('current_question_index', 0))
    progress['score'] = int(progress.get('score', 0))

    if current_idx >= len(all_questions):
        flash(f"Quiz completed! Score: {progress['score']}/{len(all_questions)}", 'success')
        new_score = Score(
            quiz_id=quiz_id,
            user_id=current_user.id,
            total_score=progress['score']
        )
        db.session.add(new_score)
        db.session.commit()
        session.pop('quiz_progress', None)
        session.pop('current_quiz_id', None)
        session.pop('quiz_start_time', None)
        session.pop('quiz_duration', None)
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        answer = request.form.get('answer')
        curr_question = all_questions[current_idx]
        
        if answer:
            if answer == curr_question.correct_option:
                progress['score'] = progress['score'] + 1  
            progress['answered_questions'][str(curr_question.id)] = answer
        
        if action == 'submit' or current_idx == len(all_questions) - 1:
            flash(f"Quiz completed! Score: {progress['score']}/{len(all_questions)}", 'success')
            new_score = Score(
                quiz_id=quiz_id,
                user_id=current_user.id,
                total_score=progress['score']
            )
            db.session.add(new_score)
            db.session.commit()
            session.pop('quiz_progress', None)
            session.pop('current_quiz_id', None)
            session.pop('quiz_start_time', None)
            session.pop('quiz_duration', None)
            return redirect(url_for('user_dashboard'))
        
        progress['current_question_index'] = current_idx + 1
        session['quiz_progress'] = progress
        session.modified = True
        return redirect(url_for('attempt_quiz', quiz_id=quiz_id))

    curr_q = all_questions[current_idx]
    question_data = {
        'text': curr_q.question_statement,
        'options': [curr_q.option1, curr_q.option2, curr_q.option3, curr_q.option4],
        'correct_option': curr_q.correct_option
    }
    
    return render_template('user/start_quiz.html',
                          quiz_id=quiz_id,
                          question=question_data,
                          current_question=current_idx + 1,
                          total_questions=len(all_questions),
                          timer=f"{remaining // 60:02d}:{remaining % 60:02d}",
                          remaining_seconds=remaining)

@app.route('/scores')
@login_required
def view_scores():

    score_records = db.session.query(
        Score.quiz_id,
        Score.timestamp,
        Score.total_score,
        Quiz.date_of_quiz,
        Quiz.duration,
        db.func.count(Question.id).label('num_questions')
    ).join(Quiz, Quiz.id == Score.quiz_id) \
     .join(Question, Question.quiz_id == Score.quiz_id) \
     .filter(Score.user_id == current_user.id) \
     .group_by(Score.quiz_id, Score.timestamp, Score.total_score, Quiz.date_of_quiz, Quiz.duration).all()

    scores_list = []
    for rec in score_records:
        scores_list.append({
            "quiz_id": rec.quiz_id,
            "date": rec.timestamp.strftime("%d/%m/%Y"),
            "num_questions": rec.num_questions,
            "total_score": rec.total_score,
            "total_possible_score": rec.num_questions 
        })

    return render_template('user/scores.html', scores=scores_list, user_name=current_user.full_name)

@app.route('/summary')
@login_required
def user_summary():
    if current_user.role == 'admin':
        logger.debug("User is admin, redirecting to admin_overview...")
        return redirect(url_for('admin_overview'))
    
    try:
        logger.debug(f"Current user: {current_user.id}, role: {current_user.role}")
        
   
        logger.debug("Step 1: Fetching subject-wise total scores...")
        subjects = db.session.query(Subject).count()
        chapters = db.session.query(Chapter).count()
        quizzes = db.session.query(Quiz).count()
        scores = db.session.query(Score).filter(Score.user_id == current_user.id).count()
        logger.debug(f"Subjects: {subjects}, Chapters: {chapters}, Quizzes: {quizzes}, Scores: {scores}")

        if subjects == 0 or chapters == 0 or quizzes == 0 or scores == 0:
            logger.debug("One or more required tables are empty, skipping subject_scores query...")
            subject_scores = []
        else:
            subject_scores = db.session.query(
                Subject.name, db.func.sum(Score.total_score).label('total_score')
            ).join(Chapter, Chapter.subject_id == Subject.id) \
             .join(Quiz, Quiz.chapter_id == Chapter.id) \
             .join(Score, Score.quiz_id == Quiz.id) \
             .filter(Score.user_id == current_user.id) \
             .group_by(Subject.name).all()
        logger.debug(f"Subject scores: {subject_scores}")

        
        logger.debug("Step 2: Fetching month-wise quiz attempts...")
        score_entries = db.session.query(Score).filter(Score.user_id == current_user.id).all()
        logger.debug(f"Score entries for user: {[(s.id, s.timestamp) for s in score_entries]}")

        if not score_entries:
            logger.debug("No score entries found, skipping month_attempts query...")
            month_attempts = []
        else:
            month_attempts = db.session.query(
                db.func.strftime('%Y-%m', Score.timestamp).label('month'),
                db.func.count(Score.id).label('attempts')
            ).filter(Score.user_id == current_user.id) \
             .filter(Score.timestamp.isnot(None)) \
             .group_by(db.func.strftime('%Y-%m', Score.timestamp)).all()
        logger.debug(f"Month attempts: {month_attempts}")


        logger.debug("Step 3: Checking if data exists...")
        if not subject_scores and not month_attempts:
            logger.debug("No data found for charts, flashing message...")
            flash("No quiz attempts found. Please attempt some quizzes to see summary data.", "info")

     
        logger.debug("Step 4: Formatting data for charts...")
        scores_labels = [str(s[0]) for s in subject_scores] if subject_scores else []  
        scores_values = []
        for s in subject_scores:
            value = s[1]
            if value is not None:
                try:
                    scores_values.append(float(value)) 
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid score value: {value}, using 0 instead. Error: {str(e)}")
                    scores_values.append(0.0)
            else:
                scores_values.append(0.0)

        attempts_labels = [str(a[0]) for a in month_attempts] if month_attempts else [] 
        attempts_values = []
        for a in month_attempts:
            value = a[1]
            try:
                attempts_values.append(int(value))  
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid attempt value: {value}, using 0 instead. Error: {str(e)}")
                attempts_values.append(0)

    
        import json
        scores_chart = {
            "labels": scores_labels,
            "values": scores_values,
            "values_json": json.dumps(scores_values) 
        }
        attempts_chart = {
            "labels": attempts_labels,
            "values": attempts_values,
            "values_json": json.dumps(attempts_values) 
        }
        logger.debug(f"Scores chart: {scores_chart}")
        logger.debug(f"Attempts chart: {attempts_chart}")

        logger.debug("Step 6: Fetching user name...")
        user_name = str(getattr(current_user, 'full_name', 'User'))  
        logger.debug(f"User name: {user_name}")

        logger.debug("Step 7: Rendering summary.html...")
        return render_template('user/summary.html', 
                              scores_chart=scores_chart, 
                              attempts_chart=attempts_chart, 
                              user_name=user_name)
    except Exception as e:
        logger.error(f"Error in user_summary: {str(e)}", exc_info=True)
        flash(f"Error loading summary: {str(e)}", "danger")
        return redirect(url_for('user_dashboard'))
    
@app.route('/search', methods=['GET'])
@login_required
def search_user():
    if current_user.role == 'admin':
        return redirect(url_for('admin_search'))
    search_term = request.args.get('search', '').strip()
    if not search_term:
        flash("Please enter a search term.", "warning")
        return redirect(url_for('user_dashboard'))

    # Quiz search kro by subject, chapter, date, and scores se 
    quizzes_query = db.session.query(
        Quiz, Chapter, Subject, Score
    ).join(Chapter, Quiz.chapter_id == Chapter.id) \
     .join(Subject, Chapter.subject_id == Subject.id) \
     .outerjoin(Score, db.and_(Score.quiz_id == Quiz.id, Score.user_id == current_user.id)) \
     .filter(
        db.or_(
            Subject.name.ilike(f"%{search_term}%"),
            Chapter.name.ilike(f"%{search_term}%"),
            Quiz.date_of_quiz.ilike(f"%{search_term}%"),
            Quiz.title.ilike(f"%{search_term}%")
        )
    ).all()

    search_results = []
    for quiz, chapter, subject, score in quizzes_query:
        num_questions = Question.query.filter_by(quiz_id=quiz.id).count()
        score_value = score.total_score if score else "Not Attempted"
        search_results.append({
            'id': quiz.id,
            'title': quiz.title,
            'details': f"Subject: {subject.name}, Chapter: {chapter.name}, Date: {quiz.date_of_quiz.strftime('%d/%m/%Y')}, Score: {score_value}/{num_questions}"
        })

    return render_template('user/user_search.html', results=search_results, user_name=current_user.full_name)

@app.route('/view_quiz/<int:quiz_id>')
@login_required
def view_quiz(quiz_id):
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter = Chapter.query.get(quiz.chapter_id)
    subject = Subject.query.get(chapter.subject_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    num_questions = len(questions)  # number of questions count krega
    return render_template('user/view_quiz.html',
                          quiz=quiz,
                          chapter=chapter,
                          subject=subject,
                          questions=questions,
                          num_questions=num_questions)

def setup_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin',
                              password=generate_password_hash('admin123'),
                              role='admin')
            db.session.add(admin_user)
            db.session.commit()

if __name__ == '__main__':
    setup_database()
    app.run(debug=True)