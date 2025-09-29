from flask import Blueprint, render_template, redirect, url_for, flash, request, send_from_directory, current_app, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from app import db, bcrypt, socketio
from app.models import User, Task, Notification
from app.forms import LoginForm, RegisterForm, TaskForm, StatusForm, ValidationForm
from werkzeug.utils import secure_filename
from flask_socketio import join_room, emit
import os
import uuid
from datetime import datetime
import magic

bp = Blueprint('main', __name__)

def is_admin():
    return current_user.is_authenticated and current_user.role == 'admin'

def allowed_file(file):
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(file.read(1024))
    file.seek(0)
    return file_type in ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']

def send_notification(user_id, message, task_id=None):
    notification = Notification(user_id=user_id, message=message, task_id=task_id)
    db.session.add(notification)
    db.session.commit()
    socketio.emit('notification', {
        'message': message,
        'task_id': task_id,
        'created_at': notification.created_at.isoformat()
    }, room=str(user_id))
    current_app.logger.info(f"Emitted notification to room {user_id}: {message}")

@socketio.on('join')
def handle_join(data):
    user_id = str(data.get('user_id'))
    if user_id:
        join_room(user_id)
        emit('joined', {'room': user_id})
        current_app.logger.info(f"User joined room {user_id}")

@bp.route('/')
def index():
    return redirect(url_for('main.login'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('Login failed. Check email or password.', 'danger')
    return render_template('login.html', form=form)

@bp.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not is_admin():
        flash('Only admins can register users.', 'danger')
        return redirect(url_for('main.dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('register.html', form=form)

@bp.route('/dashboard')
@login_required
def dashboard():
    if is_admin():
        tasks = Task.query.all()
        users = User.query.filter_by(role='user').all()
        return render_template('admin_dashboard.html', tasks=tasks, users=users)
    else:
        tasks = Task.query.filter_by(assigned_to_id=current_user.id).all()
        return render_template('user_dashboard.html', tasks=tasks, user=current_user)

@bp.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if not is_admin():
        flash('Only admins can create tasks.', 'danger')
        return redirect(url_for('main.dashboard'))
    form = TaskForm()
    form.assigned_to.choices = [(u.id, u.username) for u in User.query.filter_by(role='user').all()]
    if form.validate_on_submit():
        if form.document.data:
            if allowed_file(form.document.data):
                    original = secure_filename(form.document.data.filename)
                    unique = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}_{original}"
                    filename = unique
                    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                    form.document.data.save(file_path)
                    task = Task(title=form.title.data, description=form.description.data, document_path=filename,
                                assigned_to_id=form.assigned_to.data, created_by_id=current_user.id)
                    db.session.add(task)
                    db.session.commit()
                    try:
                        send_notification(task.assigned_to_id, f"Nouvelle tâche assignée: {task.title}", task.id)
                    except Exception:
                        pass
                    flash('Task created successfully.', 'success')
                    return redirect(url_for('main.dashboard'))
            else:
                flash('Invalid file type. Only PDF, DOC, or DOCX allowed.', 'danger')
        else:
            flash('No file uploaded.', 'danger')
    return render_template('create_task.html', form=form)

@bp.route('/update_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    if current_user.id != task.assigned_to_id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))
    form = StatusForm()
    if form.validate_on_submit():
        task.status = form.status.data
        if form.status.data == 'Completed' and form.confirmation_file.data:
            original = secure_filename(form.confirmation_file.data.filename)
            filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}_{original}"
            if allowed_file(form.confirmation_file.data):
                confirmation_paths = task.confirmation_files or []
                file_path = os.path.join(current_app.config['CONFIRMATION_FOLDER'], filename)
                form.confirmation_file.data.save(file_path)
                confirmation_paths.append(filename)
                task.confirmation_files = confirmation_paths
            else:
                flash(f'Invalid file type: {filename}. Only PDF, DOC, or DOCX allowed.', 'danger')
                return render_template('update_task.html', form=form, task=task)
        db.session.commit()
        try:
            send_notification(task.created_by_id, f"Statut mis à jour pour '{task.title}': {task.status}", task.id)
        except Exception:
            pass
        flash('Task updated successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    form.status.data = task.status
    return render_template('update_task.html', form=form, task=task)

@bp.route('/validate_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def validate_task(task_id):
    if not is_admin():
        flash('Only admins can validate tasks.', 'danger')
        return redirect(url_for('main.dashboard'))
    task = Task.query.get_or_404(task_id)
    if task.status != 'Completed':
        flash('Task must be completed before validation.', 'danger')
        return redirect(url_for('main.dashboard'))
    form = ValidationForm()
    if form.validate_on_submit():
        task.validated = True
        db.session.commit()
        try:
            send_notification(task.assigned_to_id, f"Votre tâche '{task.title}' a été validée.", task.id)
        except Exception:
            pass
        flash('Task validated successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('validate_task.html', form=form, task=task)

@bp.route('/download/<path:filename>')
@login_required
def download_file(filename):
    task = Task.query.filter((Task.document_path == filename) | (Task.confirmation_files.contains(filename))).first()
    if task and (current_user.id == task.assigned_to_id or is_admin()):
        folder = current_app.config['CONFIRMATION_FOLDER'] if filename in (task.confirmation_files or []) else current_app.config['UPLOAD_FOLDER']
        return send_from_directory(folder, filename, as_attachment=True)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('main.dashboard'))

@bp.route('/notifications/history')
@login_required
def notifications_history():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(50).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({
        'unread_count': unread_count,
        'items': [
        {
            'id': n.id,
            'message': n.message,
            'task_id': n.task_id,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat()
        } for n in notifications
        ]
    })

@bp.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def notifications_mark_all_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({Notification.is_read: True})
    db.session.commit()
    return jsonify({'status': 'ok'})

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))