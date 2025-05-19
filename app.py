from flask import Flask, render_template, request, redirect, url_for, send_file, session, flash, g
import sqlite3
from datetime import datetime, timedelta
import io
import csv
import bcrypt
from functools import wraps
import secrets
import string

app = Flask(__name__)
app.secret_key = '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d'

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS candidates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        email TEXT,
        address TEXT,
        languages TEXT,
        skills TEXT,
        preferred_shift TEXT,
        comments TEXT,
        status TEXT DEFAULT 'Awaiting Interview',
        interview_datetime TEXT,
        job_id INTEGER,
        drivers_license TEXT,
        work_permit TEXT,
        work_experience TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (job_id) REFERENCES jobs(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        shift TEXT,
        company TEXT,
        requirements TEXT,
        duration TEXT,
        job_address TEXT,
        start_date TEXT,
        end_date TEXT,
        hiring_number INTEGER,
        assigned_count INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS interview_slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        datetime TEXT NOT NULL UNIQUE,
        notes TEXT,
        is_available INTEGER DEFAULT 1
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        credentials TEXT NOT NULL
    )''')
    c.execute("PRAGMA table_info(candidates)")
    columns = [col[1] for col in c.fetchall()]
    if 'created_at' not in columns:
        c.execute("ALTER TABLE candidates ADD COLUMN created_at TIMESTAMP")
        c.execute("UPDATE candidates SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT credentials FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if not user or user[0] != 'Admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_user_data():
    g.user_name = None
    g.is_admin = False
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT full_name, credentials FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if user:
            g.user_name = user[0]
            g.is_admin = user[1] == 'Admin'

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            session['user_id'] = user[0]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        credentials = request.form['credentials']
        
        if not (full_name and username and password and credentials):
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (full_name, username, password, credentials) VALUES (?, ?, ?, ?)",
                      (full_name, username, hashed_password.decode('utf-8'), credentials))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username already exists.', 'error')
            return render_template('register.html')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT full_name, username, credentials FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('profile.html', user=user)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/manage_users')
@admin_required
def manage_users():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, full_name, username, credentials FROM users")
    users = c.fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        credentials = request.form['credentials']
        
        if not (full_name and username and password and credentials):
            flash('All fields are required.', 'error')
            return render_template('add_user.html')
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (full_name, username, password, credentials) VALUES (?, ?, ?, ?)",
                      (full_name, username, hashed_password.decode('utf-8'), credentials))
            conn.commit()
            flash('User added successfully!', 'success')
            conn.close()
            return redirect(url_for('manage_users'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username already exists.', 'error')
            return render_template('add_user.html')
    return render_template('add_user.html')

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        credentials = request.form['credentials']
        
        if not (full_name and username and credentials):
            flash('All fields are required.', 'error')
            c.execute("SELECT id, full_name, username, credentials FROM users WHERE id = ?", (id,))
            user = c.fetchone()
            conn.close()
            return render_template('edit_user.html', user=user)
        
        try:
            c.execute("UPDATE users SET full_name = ?, username = ?, credentials = ? WHERE id = ?",
                      (full_name, username, credentials, id))
            conn.commit()
            flash('User updated successfully!', 'success')
            conn.close()
            return redirect(url_for('manage_users'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username already exists.', 'error')
            c.execute("SELECT id, full_name, username, credentials FROM users WHERE id = ?", (id,))
            user = c.fetchone()
            return render_template('edit_user.html', user=user)
    
    c.execute("SELECT id, full_name, username, credentials FROM users WHERE id = ?", (id,))
    user = c.fetchone()
    conn.close()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>')
@admin_required
def delete_user(id):
    if id == session['user_id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('manage_users'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE id = ?", (id,))
    user = c.fetchone()
    if user:
        c.execute("DELETE FROM users WHERE id = ?", (id,))
        conn.commit()
        flash('User deleted successfully!', 'success')
    else:
        flash('User not found.', 'error')
    conn.close()
    return redirect(url_for('manage_users'))

@app.route('/reset_password/<int:id>', methods=['POST'])
@admin_required
def reset_password(id):
    if id == session['user_id']:
        flash('You cannot reset your own password.', 'error')
        return redirect(url_for('manage_users'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE id = ?", (id,))
    user = c.fetchone()
    if not user:
        flash('User not found.', 'error')
        conn.close()
        return redirect(url_for('manage_users'))
    
    # Generate random 12-character password
    characters = string.ascii_letters + string.digits + string.punctuation
    new_password = ''.join(secrets.choice(characters) for _ in range(12))
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password.decode('utf-8'), id))
    conn.commit()
    conn.close()
    
    flash(f'Password reset successfully! New password: {new_password}', 'success')
    return redirect(url_for('manage_users'))

@app.route('/dashboard')
@login_required
def dashboard():
    today = datetime.now().strftime('%Y-%m-%d')
    seven_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM candidates")
    total_candidates = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM candidates WHERE status = 'Awaiting Interview'")
    awaiting_interview = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM candidates WHERE status = 'Interview Scheduled'")
    interview_scheduled = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM candidates WHERE status = 'Awaiting Job'")
    awaiting_job = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM candidates WHERE status = 'Job Assigned'")
    job_assigned = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM jobs")
    total_jobs = c.fetchone()[0]
    c.execute("SELECT id, name, interview_datetime FROM candidates WHERE status = 'Interview Scheduled' AND interview_datetime LIKE ? ORDER BY interview_datetime", (f'{today}%',))
    todays_interviews = c.fetchall()
    c.execute("SELECT id, name FROM candidates WHERE status = 'Awaiting Interview'")
    schedule_interview_tasks = c.fetchall()
    c.execute("SELECT id, name FROM candidates WHERE status = 'Awaiting Job'")
    raw_tasks = c.fetchall()
    assign_job_tasks = []
    for task in raw_tasks:
        try:
            task_id = int(task[0])
            if task_id > 0:
                assign_job_tasks.append((task_id, task[1]))
            else:
                print(f"Skipping invalid candidate ID: {task[0]} (non-positive)")
        except (ValueError, TypeError):
            print(f"Skipping invalid candidate ID: {task[0]} (non-integer)")
    print("Assign Job Tasks (Filtered):", assign_job_tasks)
    c.execute("SELECT id, name FROM candidates WHERE status = 'Job Assigned'")
    call_to_start_job_tasks = c.fetchall()
    c.execute("SELECT COUNT(*) FROM candidates WHERE created_at >= ?", (seven_days_ago,))
    new_candidates = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM candidates WHERE status = 'Awaiting Job' AND interview_datetime >= ?", (seven_days_ago,))
    interviews_completed = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM candidates WHERE status = 'Job Assigned' AND job_id IS NOT NULL AND created_at >= ?", (seven_days_ago,))
    assigned_jobs = c.fetchone()[0]
    conn.close()
    return render_template('dashboard.html', 
                         total_candidates=total_candidates,
                         awaiting_interview=awaiting_interview,
                         interview_scheduled=interview_scheduled,
                         awaiting_job=awaiting_job,
                         job_assigned=job_assigned,
                         total_jobs=total_jobs,
                         todays_interviews=todays_interviews,
                         today=today,
                         schedule_interview_tasks=schedule_interview_tasks,
                         assign_job_tasks=assign_job_tasks,
                         call_to_start_job_tasks=call_to_start_job_tasks,
                         new_candidates=new_candidates,
                         interviews_completed=interviews_completed,
                         assigned_jobs=assigned_jobs)

@app.route('/candidate/<int:id>', methods=['GET', 'POST'])
@login_required
def candidate_profile(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if request.method == 'POST':
        comments = request.form['comments']
        c.execute("UPDATE candidates SET comments = ? WHERE id = ?", (comments, id))
        conn.commit()
        flash('Comments updated successfully!', 'success')
        conn.close()
        return redirect(url_for('candidate_profile', id=id))
    c.execute('''SELECT c.*, j.type, j.company, j.start_date, j.end_date
                 FROM candidates c
                 LEFT JOIN jobs j ON c.job_id = j.id
                 WHERE c.id = ?''', (id,))
    candidate = c.fetchone()
    conn.close()
    if not candidate:
        flash('Candidate not found.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('candidate_profile.html', candidate=candidate)

@app.route('/job/<int:id>', methods=['GET'])
@login_required
def job_details(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT id, type, company, job_address, shift, requirements, duration, start_date, end_date, hiring_number, assigned_count
                 FROM jobs WHERE id = ?''', (id,))
    job = c.fetchone()
    conn.close()
    if not job:
        flash('Job not found.', 'error')
        return redirect(url_for('job_list'))
    status = 'Open' if job[9] is None or job[10] < job[9] else 'Closed'
    job = job[:9] + (status, job[9], job[10])
    return render_template('job_details.html', job=job)

@app.route('/interview/<int:id>', methods=['GET'])
@login_required
def interview_details(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT c.id, c.name, c.email, c.interview_datetime, c.status, j.type, j.company, j.job_address
                 FROM candidates c
                 LEFT JOIN jobs j ON c.job_id = j.id
                 WHERE c.id = ? AND c.status = 'Interview Scheduled' ''', (id,))
    interview = c.fetchone()
    conn.close()
    if not interview:
        flash('Interview not found.', 'error')
        return redirect(url_for('interview_scheduled'))
    return render_template('interview_details.html', interview=interview)

@app.route('/interview_slot/<int:id>', methods=['GET'])
@login_required
def interview_slot_details(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT id, datetime, notes, is_available
                 FROM interview_slots WHERE id = ?''', (id,))
    slot = c.fetchone()
    if not slot:
        conn.close()
        flash('Interview slot not found.', 'error')
        return redirect(url_for('interview_slots'))
    c.execute('''SELECT id, name FROM candidates
                 WHERE interview_datetime = ? AND status = 'Interview Scheduled' ''', (slot[1],))
    candidate = c.fetchone()
    conn.close()
    availability = 'Available' if slot[3] else 'Assigned'
    slot = slot[:3] + (availability, slot[3])
    return render_template('interview_slot_details.html', slot=slot, candidate=candidate)

@app.route('/complete_interview/<int:id>')
@login_required
def complete_interview(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT status, interview_datetime FROM candidates WHERE id = ?", (id,))
    result = c.fetchone()
    if result:
        current_status, interview_datetime = result
        if current_status == 'Interview Scheduled':
            c.execute("UPDATE candidates SET status = 'Awaiting Job' WHERE id = ?", (id,))
            if interview_datetime:
                c.execute("UPDATE interview_slots SET is_available = 1 WHERE datetime = ?", (interview_datetime,))
            conn.commit()
            flash('Interview marked as completed.', 'success')
        else:
            flash('Cannot complete interview; candidate is not scheduled.', 'error')
    else:
        flash('Candidate not found.', 'error')
    conn.close()
    return redirect(url_for('interview_scheduled'))

@app.route('/cancel_interview/<int:id>')
@login_required
def cancel_interview(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT status, interview_datetime FROM candidates WHERE id = ?", (id,))
    result = c.fetchone()
    if result:
        current_status, interview_datetime = result
        if current_status == 'Interview Scheduled':
            c.execute("UPDATE candidates SET status = 'Awaiting Interview', interview_datetime = NULL WHERE id = ?", (id,))
            if interview_datetime:
                c.execute("UPDATE interview_slots SET is_available = 1 WHERE datetime = ?", (interview_datetime,))
            conn.commit()
            flash('Interview cancelled successfully.', 'success')
        else:
            flash('Cannot cancel interview; candidate is not scheduled.', 'error')
    else:
        flash('Candidate not found.', 'error')
    conn.close()
    return redirect(url_for('interview_scheduled'))

@app.route('/reschedule_interview/<int:id>', methods=['GET', 'POST'])
@login_required
def reschedule_interview(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, name, status, interview_datetime FROM candidates WHERE id = ?", (id,))
    candidate = c.fetchone()
    if not candidate:
        conn.close()
        flash('Candidate not found.', 'error')
        return redirect(url_for('interview_scheduled'))
    if candidate[2] != 'Interview Scheduled':
        conn.close()
        flash('Candidate is not scheduled for an interview.', 'error')
        return redirect(url_for('interview_scheduled'))
    
    if request.method == 'POST':
        slot_id = request.form['slot_id']
        c.execute("SELECT datetime FROM interview_slots WHERE id = ? AND is_available = 1", (slot_id,))
        slot = c.fetchone()
        if slot:
            old_datetime = candidate[3]
            c.execute("UPDATE candidates SET interview_datetime = ? WHERE id = ?", (slot[0], id))
            c.execute("UPDATE interview_slots SET is_available = 0 WHERE id = ?", (slot_id,))
            if old_datetime:
                c.execute("UPDATE interview_slots SET is_available = 1 WHERE datetime = ?", (old_datetime,))
            conn.commit()
            flash('Interview rescheduled successfully!', 'success')
        else:
            flash('Selected slot is not available.', 'error')
        conn.close()
        return redirect(url_for('interview_scheduled'))
    
    c.execute("SELECT id, datetime FROM interview_slots WHERE is_available = 1")
    slots = c.fetchall()
    conn.close()
    return render_template('reschedule_interview.html', candidate_id=id, candidate_name=candidate[1], slots=slots)

@app.route('/update_candidate_status/<int:id>', methods=['POST'])
@login_required
def update_candidate_status(id):
    status = request.form.get('status')
    valid_statuses = ['Awaiting Interview', 'Interview Scheduled', 'Awaiting Job', 'Job Assigned']
    if status not in valid_statuses:
        flash('Invalid status selected.', 'error')
        return redirect(url_for('candidate_list'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE candidates SET status = ? WHERE id = ?", (status, id))
    conn.commit()
    conn.close()
    flash(f'Status updated to "{status}" successfully!', 'success')
    return redirect(url_for('candidate_list'))

@app.route('/add_candidate', methods=['GET', 'POST'])
@login_required
def add_candidate():
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        address = request.form['address']
        languages = request.form['languages']
        skills = request.form['skills']
        preferred_shift = request.form['preferred_shift']
        comments = request.form['comments']
        drivers_license = request.form['drivers_license']
        work_permit = request.form['work_permit']
        work_experience = request.form['work_experience']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''INSERT INTO candidates (name, phone, email, address, languages, skills, preferred_shift, comments, status, drivers_license, work_permit, work_experience, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Awaiting Interview', ?, ?, ?, CURRENT_TIMESTAMP)''',
                  (name, phone, email, address, languages, skills, preferred_shift, comments, drivers_license, work_permit, work_experience))
        conn.commit()
        conn.close()
        flash('Candidate added successfully!', 'success')
        return redirect(url_for('candidate_list'))
    return render_template('add_candidate.html')

@app.route('/edit_candidate/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_candidate(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        address = request.form['address']
        languages = request.form['languages']
        skills = request.form['skills']
        preferred_shift = request.form['preferred_shift']
        comments = request.form['comments']
        drivers_license = request.form['drivers_license']
        work_permit = request.form['work_permit']
        work_experience = request.form['work_experience']
        c.execute('''UPDATE candidates SET name = ?, phone = ?, email = ?, address = ?, languages = ?, skills = ?, preferred_shift = ?, comments = ?, drivers_license = ?, work_permit = ?, work_experience = ?
                     WHERE id = ?''', (name, phone, email, address, languages, skills, preferred_shift, comments, drivers_license, work_permit, work_experience, id))
        conn.commit()
        conn.close()
        flash('Candidate updated successfully!', 'success')
        return redirect(url_for('candidate_list'))
    c.execute("SELECT * FROM candidates WHERE id = ?", (id,))
    candidate = c.fetchone()
    conn.close()
    return render_template('edit_candidate.html', candidate=candidate)

@app.route('/delete_candidate/<int:id>')
@login_required
def delete_candidate(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT job_id, interview_datetime FROM candidates WHERE id = ?", (id,))
    result = c.fetchone()
    job_id, interview_datetime = result[0], result[1]
    if job_id:
        c.execute("UPDATE jobs SET assigned_count = assigned_count - 1 WHERE id = ? AND assigned_count > 0", (job_id,))
    if interview_datetime:
        c.execute("UPDATE interview_slots SET is_available = 1 WHERE datetime = ?", (interview_datetime,))
    c.execute("DELETE FROM candidates WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash('Candidate deleted successfully!', 'success')
    return redirect(url_for('candidate_list'))

@app.route('/candidate_list')
@login_required
def candidate_list():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT c.id, c.name, c.email, c.status, j.type
                 FROM candidates c
                 LEFT JOIN jobs j ON c.job_id = j.id''')
    candidates = c.fetchall()
    conn.close()
    return render_template('candidate_list.html', candidates=candidates)

@app.route('/interview_scheduled')
@login_required
def interview_scheduled():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT c.id, c.name, c.email, c.interview_datetime, c.status, j.type, j.company, j.job_address
                 FROM candidates c
                 LEFT JOIN jobs j ON c.job_id = j.id
                 WHERE c.status = 'Interview Scheduled' ''')
    candidates = c.fetchall()
    c.execute("SELECT id, type FROM jobs WHERE hiring_number IS NULL OR assigned_count < hiring_number")
    jobs = c.fetchall()
    c.execute("SELECT id, datetime FROM interview_slots WHERE is_available = 1")
    slots = c.fetchall()
    c.execute("SELECT id, name FROM candidates WHERE status = 'Awaiting Interview'")
    available_candidates = c.fetchall()
    conn.close()
    return render_template('interview_scheduled.html', candidates=candidates, jobs=jobs, slots=slots, available_candidates=available_candidates, is_admin=g.is_admin)

@app.route('/awaiting_job')
@login_required
def awaiting_job():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM candidates WHERE status = 'Awaiting Job'")
    candidates = c.fetchall()
    c.execute("SELECT id, type FROM jobs WHERE hiring_number IS NULL OR (hiring_number IS NOT NULL AND assigned_count < hiring_number)")
    jobs = c.fetchall()
    conn.close()
    return render_template('awaiting_job.html', candidates=candidates, jobs=jobs)

@app.route('/temp_jobs')
@login_required
def temp_jobs():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT c.id, c.name, c.phone, c.email, c.job_id, j.type, j.company, j.duration
                 FROM candidates c
                 LEFT JOIN jobs j ON c.job_id = j.id
                 WHERE c.status = 'Job Assigned' ''')
    candidates = c.fetchall()
    conn.close()
    return render_template('temp_jobs.html', candidates=candidates)

@app.route('/schedule_interview/<int:id>', methods=['GET', 'POST'])
@login_required
def schedule_interview(id):
    if request.method == 'POST':
        slot_id = request.form['slot_id']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT datetime FROM interview_slots WHERE id = ? AND is_available = 1", (slot_id,))
        slot = c.fetchone()
        if slot:
            c.execute("UPDATE candidates SET status = 'Interview Scheduled', interview_datetime = ? WHERE id = ?", (slot[0], id))
            c.execute("UPDATE interview_slots SET is_available = 0 WHERE id = ?", (slot_id,))
            conn.commit()
            flash('Interview scheduled successfully!', 'success')
        else:
            flash('Selected slot is not available.', 'error')
        conn.close()
        return redirect(url_for('interview_scheduled'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, datetime FROM interview_slots WHERE is_available = 1")
    slots = c.fetchall()
    c.execute("SELECT name FROM candidates WHERE id = ?", (id,))
    candidate = c.fetchone()
    conn.close()
    if not candidate:
        flash('Candidate not found.', 'error')
        return redirect(url_for('interview_scheduled'))
    return render_template('interview_scheduled.html', candidate_id=id, slots=slots, candidate_name=candidate[0], is_admin=g.is_admin)

@app.route('/add_job', methods=['GET', 'POST'])
@login_required
def add_job():
    if request.method == 'POST':
        job_type = request.form['type']
        shift = request.form['shift']
        company = request.form['company']
        requirements = request.form['requirements']
        duration = request.form['duration']
        job_address = request.form['job_address']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        hiring_number = request.form['hiring_number']
        
        hiring_number = hiring_number.strip()
        hiring_number = int(hiring_number) if hiring_number else None
        if hiring_number is not None and hiring_number < 0:
            hiring_number = None
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''INSERT INTO jobs (type, shift, company, requirements, duration, job_address, start_date, end_date, hiring_number)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (job_type, shift, company, requirements, duration, job_address, start_date, end_date, hiring_number))
        conn.commit()
        conn.close()
        flash('Job added successfully!', 'success')
        return redirect(url_for('job_list'))
    return render_template('add_job.html')

@app.route('/job_list')
@login_required
def job_list():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT id, type, company, job_address, assigned_count, hiring_number
                 FROM jobs''')
    jobs_raw = c.fetchall()
    jobs = []
    for job in jobs_raw:
        status = 'Open' if job[5] is None or job[4] < job[5] else 'Closed'
        jobs.append(job[:4] + (status, job[4], job[5]))
    conn.close()
    return render_template('job_list.html', jobs=jobs)

@app.route('/edit_job/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_job(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if request.method == 'POST':
        job_type = request.form['type']
        shift = request.form['shift']
        company = request.form['company']
        requirements = request.form['requirements']
        duration = request.form['duration']
        job_address = request.form['job_address']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        hiring_number = request.form['hiring_number']
        
        hiring_number = hiring_number.strip()
        hiring_number = int(hiring_number) if hiring_number else None
        if hiring_number is not None and hiring_number < 0:
            hiring_number = None
        
        c.execute('''UPDATE jobs SET type = ?, shift = ?, company = ?, requirements = ?, duration = ?, job_address = ?, start_date = ?, end_date = ?, hiring_number = ?
                     WHERE id = ?''', (job_type, shift, company, requirements, duration, job_address, start_date, end_date, hiring_number, id))
        conn.commit()
        conn.close()
        flash('Job updated successfully!', 'success')
        return redirect(url_for('job_list'))
    c.execute("SELECT * FROM jobs WHERE id = ?", (id,))
    job = c.fetchone()
    conn.close()
    return render_template('edit_job.html', job=job)

@app.route('/delete_job/<int:id>')
@login_required
def delete_job(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM candidates WHERE job_id = ? AND status = 'Job Assigned'", (id,))
    assigned_count = c.fetchone()[0]
    if assigned_count == 0:
        c.execute("DELETE FROM jobs WHERE id = ?", (id,))
        conn.commit()
        flash('Job deleted successfully!', 'success')
    else:
        flash('Cannot delete job with assigned candidates.', 'error')
    conn.close()
    return redirect(url_for('job_list'))

@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reports():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    status_options = {
        'candidate': ['All', 'Awaiting Interview', 'Interview Scheduled', 'Awaiting Job', 'Job Assigned'],
        'jobs': ['All', 'Open', 'Closed'],
        'interview': ['All', 'Available', 'Assigned']
    }
    
    report_type = 'candidate'
    status = 'All'
    date_start = ''
    date_end = ''
    results = []
    
    if request.method == 'POST':
        report_type = request.form.get('report_type', 'candidate')
        status = request.form.get('status', 'All')
        date_start = request.form.get('date_start', '')
        date_end = request.form.get('date_end', '')
        
        if report_type not in ['candidate', 'jobs', 'interview']:
            report_type = 'candidate'
        if status not in status_options[report_type]:
            status = 'All'
        
        if report_type == 'candidate':
            query = '''SELECT c.id, c.name, c.status, c.interview_datetime, j.type, j.company, j.start_date, j.end_date
                       FROM candidates c
                       LEFT JOIN jobs j ON c.job_id = j.id'''
            conditions = []
            params = []
            if status and status != 'All':
                conditions.append("c.status = ?")
                params.append(status)
            if date_start:
                conditions.append("c.created_at >= ?")
                params.append(date_start)
            if date_end:
                conditions.append("c.created_at <= ?")
                params.append(date_end)
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        elif report_type == 'jobs':
            query = '''SELECT id, type, company, job_address,
                             CASE WHEN hiring_number IS NULL OR assigned_count < hiring_number THEN 'Open' ELSE 'Closed' END AS status,
                             start_date, end_date, hiring_number, assigned_count
                       FROM jobs'''
            conditions = []
            params = []
            if status and status != 'All':
                if status == 'Open':
                    conditions.append("(hiring_number IS NULL OR assigned_count < hiring_number)")
                elif status == 'Closed':
                    conditions.append("hiring_number IS NOT NULL AND assigned_count >= hiring_number")
            if date_start:
                conditions.append("start_date >= ?")
                params.append(date_start)
            if date_end:
                conditions.append("end_date <= ?")
                params.append(date_end)
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        elif report_type == 'interview':
            query = '''SELECT s.id, s.datetime, s.notes,
                             CASE WHEN s.is_available = 1 THEN 'Available' ELSE 'Assigned' END AS status,
                             c.name
                       FROM interview_slots s
                       LEFT JOIN candidates c ON c.interview_datetime = s.datetime AND c.status = 'Interview Scheduled' '''
            conditions = []
            params = []
            if status and status != 'All':
                conditions.append("s.is_available = ?")
                params.append(1 if status == 'Available' else 0)
            if date_start:
                conditions.append("s.datetime >= ?")
                params.append(date_start)
            if date_end:
                conditions.append("s.datetime <= ?")
                params.append(date_end)
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        if 'export_csv' in request.form:
            c.execute(query, params)
            results = c.fetchall()
            conn.close()
            
            output = io.StringIO()
            writer = csv.writer(output)
            if report_type == 'candidate':
                writer.writerow(['Candidate ID', 'Name', 'Status', 'Interview Date', 'Job Type', 'Company', 'Job Start Date', 'Job End Date'])
                for row in results:
                    writer.writerow([row[0], row[1], row[2], row[3] or 'N/A', row[4] or 'None', row[5] or 'None', row[6] or 'None', row[7] or 'None'])
            elif report_type == 'jobs':
                writer.writerow(['Job ID', 'Type', 'Company', 'Address', 'Status', 'Start Date', 'End Date', 'Hiring Number', 'Assigned Count'])
                for row in results:
                    writer.writerow([row[0], row[1], row[2], row[3], row[4], row[5] or 'N/A', row[6] or 'N/A', row[7] or 'N/A', row[8]])
            elif report_type == 'interview':
                writer.writerow(['Slot ID', 'Datetime', 'Notes', 'Status', 'Assigned Candidate'])
                for row in results:
                    writer.writerow([row[0], row[1], row[2] or 'N/A', row[3], row[4] or 'None'])
            
            output.seek(0)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'{report_type}_report_{timestamp}.csv'
            )
        
        c.execute(query, params)
        results = c.fetchall()
    
    conn.close()
    return render_template('reports.html',
                         statuses=status_options[report_type],
                         report_type=report_type,
                         status=status,
                         date_start=date_start,
                         date_end=date_end,
                         results=results)

@app.route('/interview_slots')
@login_required
def interview_slots():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, datetime, notes, is_available FROM interview_slots")
    slots_raw = c.fetchall()
    slots = [(slot[0], slot[1], slot[2], 'Available' if slot[3] else 'Assigned') for slot in slots_raw]
    conn.close()
    return render_template('interview_slots.html', slots=slots)

@app.route('/add_interview_slot', methods=['GET', 'POST'])
@admin_required
def add_interview_slot():
    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']
        notes = request.form['notes']
        if date and time:
            datetime_str = f"{date} {time}"
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            try:
                c.execute("INSERT INTO interview_slots (datetime, notes, is_available) VALUES (?, ?, 1)", (datetime_str, notes))
                conn.commit()
                flash('Interview slot added successfully!', 'success')
                conn.close()
                referrer = request.referrer or url_for('interview_slots')
                if 'interview_scheduled' in referrer:
                    return redirect(url_for('interview_scheduled'))
                return redirect(url_for('interview_slots'))
            except sqlite3.IntegrityError:
                conn.close()
                flash('This date and time is already taken.', 'error')
                return render_template('add_interview_slot.html')
        flash('Please provide both date and time.', 'error')
        return render_template('add_interview_slot.html')
    return render_template('add_interview_slot.html')

@app.route('/edit_interview_slot/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_interview_slot(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']
        notes = request.form['notes']
        if date and time:
            datetime_str = f"{date} {time}"
            try:
                c.execute("UPDATE interview_slots SET datetime = ?, notes = ? WHERE id = ?", (datetime_str, notes, id))
                conn.commit()
                flash('Interview slot updated successfully!', 'success')
                conn.close()
                return redirect(url_for('interview_slots'))
            except sqlite3.IntegrityError:
                conn.close()
                flash('This date and time is already taken.', 'error')
                return render_template('add_interview_slot.html', slot={'id': id, 'datetime': datetime_str, 'notes': notes})
        flash('Please provide both date and time.', 'error')
        conn.close()
        return render_template('add_interview_slot.html', slot={'id': id, 'datetime': request.form.get('datetime'), 'notes': notes})
    c.execute("SELECT id, datetime, notes FROM interview_slots WHERE id = ?", (id,))
    slot = c.fetchone()
    conn.close()
    return render_template('add_interview_slot.html', slot=slot)

@app.route('/delete_interview_slot/<int:id>')
@admin_required
def delete_interview_slot(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT is_available FROM interview_slots WHERE id = ?", (id,))
    is_available = c.fetchone()[0]
    if is_available:
        c.execute("DELETE FROM interview_slots WHERE id = ?", (id,))
        conn.commit()
        flash('Interview slot deleted successfully!', 'success')
    else:
        flash('Cannot delete assigned interview slot.', 'error')
    conn.close()
    return redirect(url_for('interview_slots'))

@app.route('/assign_job/<int:id>', methods=['GET', 'POST'])
@login_required
def assign_job(id):
    if request.method == 'POST':
        job_id = request.form['job_id']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT hiring_number, assigned_count FROM jobs WHERE id = ?", (job_id,))
        job = c.fetchone()
        if job:
            hiring_number = job[0]
            assigned_count = job[1]
            if hiring_number is not None and assigned_count >= hiring_number:
                conn.close()
                flash('This job is fully assigned and no longer available.', 'error')
                return redirect(url_for('assign_job', id=id))
            c.execute("UPDATE candidates SET status = 'Job Assigned', job_id = ? WHERE id = ?", (job_id, id))
            c.execute("UPDATE jobs SET assigned_count = assigned_count + 1 WHERE id = ?", (job_id,))
            conn.commit()
            flash('Job assigned successfully!', 'success')
            conn.close()
            return redirect(url_for('temp_jobs'))
        conn.close()
        flash('Invalid job selected.', 'error')
        return redirect(url_for('assign_job', id=id))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, type FROM jobs WHERE hiring_number IS NULL OR (hiring_number IS NOT NULL AND assigned_count < hiring_number)")
    jobs = c.fetchall()
    conn.close()
    return render_template('assign_job.html', candidate_id=id, jobs=jobs)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)