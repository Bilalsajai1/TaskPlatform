from flask import Blueprint, render_template, redirect, url_for, flash, request, send_from_directory, current_app, jsonify, Response
from flask_login import login_user, current_user, logout_user, login_required
from app import db, bcrypt, socketio
from app.models import User, Task, Notification, Comment, SavedFilter
from app.forms import LoginForm, RegisterForm, TaskForm, StatusForm, ValidationForm, CommentForm
from werkzeug.utils import secure_filename
from flask_socketio import join_room, emit
import os
import uuid
from datetime import datetime
from sqlalchemy import func, case
import magic

bp = Blueprint('main', __name__)

# Configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_MIME_TYPES = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
]

def is_admin():
    return current_user.is_authenticated and current_user.role == 'admin'

def allowed_file(file):
    """Validation robuste des fichiers uploadés"""
    try:
        # Vérifier la taille
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        
        if size > MAX_FILE_SIZE:
            return False, "File too large (max 10MB)"
        
        if size == 0:
            return False, "Empty file"
        
        # Vérifier le MIME type
        mime = magic.Magic(mime=True)
        file_content = file.read(8192)
        file.seek(0)
        file_type = mime.from_buffer(file_content)
        
        if file_type not in ALLOWED_MIME_TYPES:
            return False, f"Invalid file type: {file_type}"
        
        return True, None
    except Exception as e:
        current_app.logger.error(f"File validation error: {str(e)}")
        return False, "File validation failed"

def send_notification(user_id, message, task_id=None):
    """Envoie une notification avec gestion d'erreur"""
    try:
        notification = Notification(user_id=user_id, message=message, task_id=task_id)
        db.session.add(notification)
        db.session.commit()
        socketio.emit('notification', {
            'message': message,
            'task_id': task_id,
            'created_at': notification.created_at.isoformat()
        }, room=str(user_id))
        current_app.logger.info(f"Notification sent to user {user_id}: {message}")
    except Exception as e:
        current_app.logger.error(f"Failed to send notification: {str(e)}")
        db.session.rollback()

@socketio.on('join')
def handle_join(data):
    """Gestion sécurisée des connexions WebSocket"""
    if not current_user.is_authenticated:
        emit('error', {'message': 'Unauthorized'})
        return False
    
    user_id = str(current_user.id)  # Utiliser l'ID de la session authentifiée
    join_room(user_id)
    emit('joined', {'room': user_id})
    current_app.logger.info(f"User {user_id} joined WebSocket room")

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
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
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
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, 
                       password=hashed_password, role=form.role.data)
            db.session.add(user)
            db.session.commit()
            flash('User registered successfully.', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Email or username may already exist.', 'danger')
    return render_template('register.html', form=form)

@bp.route('/dashboard')
@login_required
def dashboard():
    if is_admin():
        status = request.args.get('status')
        assigned_to = request.args.get('assigned_to', type=int)
        q = request.args.get('q', type=str)
        quick = request.args.get('quick')
        page = request.args.get('page', 1, type=int)
        
        query = Task.query.options(db.joinedload(Task.assignee), db.joinedload(Task.creator))
        
        if status:
            query = query.filter(Task.status == status)
        if assigned_to:
            query = query.filter(Task.assigned_to_id == assigned_to)
        if q:
            like = f"%{q}%"
            query = query.filter((Task.title.ilike(like)) | (Task.description.ilike(like)))
        if quick == 'needs_validation':
            query = query.filter(Task.status == 'Completed', Task.validated.is_(False))
        if quick == 'overdue':
            query = query.filter(Task.due_date.isnot(None), Task.due_date < func.now(), Task.validated.is_(False))
        
        query = query.order_by(Task.timestamp.desc())
        pagination = query.paginate(page=page, per_page=10, error_out=False)
        users = User.query.filter_by(role='user').all()
        
        # Stats optimisées en une seule requête
        stats = db.session.query(
            func.count(Task.id).label('total'),
            func.sum(case((Task.validated == True, 1), else_=0)).label('validated')
        ).first()
        
        total_tasks = stats.total or 0
        validated_count = stats.validated or 0
        not_validated_count = total_tasks - validated_count
        
        status_rows = db.session.query(Task.status, func.count(Task.id))\
            .group_by(Task.status).all()
        status_counts = {row[0] or 'Unknown': row[1] for row in status_rows}
        
        per_user_rows = db.session.query(User.username, func.count(Task.id))\
            .join(Task, Task.assigned_to_id == User.id)\
            .group_by(User.username).all()
        per_user_counts = {row[0]: row[1] for row in per_user_rows}
        
        # Préparer les filtres de base
        base_filters = {}
        if status:
            base_filters['status'] = status
        if assigned_to:
            base_filters['assigned_to'] = assigned_to
        if q:
            base_filters['q'] = q
        
        return render_template(
            'admin_dashboard.html',
            tasks=pagination.items,
            users=users,
            pagination=pagination,
            current_filters={'status': status, 'assigned_to': assigned_to, 'q': q, 'quick': quick},
            base_filters=base_filters,
            status_counts=status_counts,
            total_tasks=total_tasks,
            validated_count=validated_count,
            not_validated_count=not_validated_count,
            per_user_counts=per_user_counts
        )
    else:
        page = request.args.get('page', 1, type=int)
        status_filter = request.args.get('status')
        
        query = Task.query.filter_by(assigned_to_id=current_user.id)\
            .options(db.joinedload(Task.creator))
        
        if status_filter:
            query = query.filter(Task.status == status_filter)
        
        query = query.order_by(Task.timestamp.desc())
        pagination = query.paginate(page=page, per_page=20, error_out=False)
        
        return render_template('user_dashboard.html', 
                             tasks=pagination.items, 
                             pagination=pagination,
                             user=current_user,
                             current_status=status_filter)

@bp.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if not is_admin():
        flash('Only admins can create tasks.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    form = TaskForm()
    form.assigned_to.choices = [(u.id, u.username) for u in User.query.filter_by(role='user').all()]
    
    if form.validate_on_submit():
        if not form.document.data:
            flash('No file uploaded.', 'danger')
            return render_template('create_task.html', form=form)
        
        is_valid, error_msg = allowed_file(form.document.data)
        if not is_valid:
            flash(f'Invalid file: {error_msg}', 'danger')
            return render_template('create_task.html', form=form)
        
        try:
            original = secure_filename(form.document.data.filename)
            unique = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}_{original}"
            filename = unique
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            form.document.data.save(file_path)
            
            tags = []
            if form.tags.data:
                tags = [t.strip() for t in form.tags.data.split(',') if t.strip()]
            
            task = Task(
                title=form.title.data,
                description=form.description.data,
                document_path=filename,
                assigned_to_id=form.assigned_to.data,
                created_by_id=current_user.id,
                due_date=form.due_date.data,
                priority=form.priority.data,
                tags=tags
            )
            db.session.add(task)
            db.session.commit()
            
            send_notification(task.assigned_to_id, f"Nouvelle tâche assignée: {task.title}", task.id)
            flash('Task created successfully.', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Task creation error: {str(e)}")
            flash('Task creation failed.', 'danger')
    
    return render_template('create_task.html', form=form)

@bp.route('/update_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def update_task(task_id):
    task = Task.query.options(
        db.joinedload(Task.assignee),
        db.joinedload(Task.creator)
    ).get_or_404(task_id)
    
    if current_user.id != task.assigned_to_id and not is_admin():
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if task.validated:
        flash('Task already validated and cannot be updated.', 'warning')
        return redirect(url_for('main.dashboard'))
    
    form = StatusForm()
    comment_form = CommentForm()
    
    if form.validate_on_submit() and 'submit' in request.form:
        try:
            task.status = form.status.data
            
            if form.status.data == 'Completed' and form.confirmation_file.data:
                is_valid, error_msg = allowed_file(form.confirmation_file.data)
                if not is_valid:
                    flash(f'Invalid confirmation file: {error_msg}', 'danger')
                    return render_template('update_task.html', form=form, task=task, 
                                         comment_form=comment_form, comments=[])
                
                original = secure_filename(form.confirmation_file.data.filename)
                filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}_{original}"
                confirmation_paths = task.confirmation_files or []
                file_path = os.path.join(current_app.config['CONFIRMATION_FOLDER'], filename)
                form.confirmation_file.data.save(file_path)
                confirmation_paths.append(filename)
                task.confirmation_files = confirmation_paths
            
            db.session.commit()
            send_notification(task.created_by_id, f"Statut mis à jour pour '{task.title}': {task.status}", task.id)
            flash('Task updated successfully.', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Task update error: {str(e)}")
            flash('Task update failed.', 'danger')
    
    if comment_form.validate_on_submit() and 'content' in request.form:
        try:
            c = Comment(task_id=task.id, user_id=current_user.id, content=comment_form.content.data)
            db.session.add(c)
            db.session.commit()
            
            target_id = task.created_by_id if current_user.id == task.assigned_to_id else task.assigned_to_id
            send_notification(target_id, f"Nouveau commentaire sur '{task.title}'", task.id)
            return redirect(url_for('main.update_task', task_id=task.id))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Comment error: {str(e)}")
            flash('Failed to add comment.', 'danger')
    
    form.status.data = task.status
    comments = Comment.query.filter_by(task_id=task.id)\
        .options(db.joinedload(Comment.user))\
        .order_by(Comment.created_at.asc()).all()
    
    return render_template('update_task.html', form=form, task=task, 
                         comment_form=comment_form, comments=comments)

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
        try:
            task.validated = True
            db.session.commit()
            send_notification(task.assigned_to_id, f"Votre tâche '{task.title}' a été validée.", task.id)
            flash('Task validated successfully.', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Validation error: {str(e)}")
            flash('Validation failed.', 'danger')
    
    return render_template('validate_task.html', form=form, task=task)

@bp.route('/download/<path:filename>')
@login_required
def download_file(filename):
    task = Task.query.filter(
        (Task.document_path == filename) | (Task.confirmation_files.contains([filename]))
    ).first()
    
    if not task:
        flash('File not found.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if current_user.id != task.assigned_to_id and not is_admin():
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    folder = current_app.config['CONFIRMATION_FOLDER'] if filename in (task.confirmation_files or []) \
             else current_app.config['UPLOAD_FOLDER']
    
    return send_from_directory(folder, filename, as_attachment=True)

@bp.route('/filters', methods=['GET', 'POST'])
@login_required
def filters():
    if request.method == 'POST':
        name = request.json.get('name')
        params = request.json.get('params') or {}
        if not name:
            return jsonify({'error': 'name required'}), 400
        
        try:
            sf = SavedFilter(user_id=current_user.id, name=name, params=params)
            db.session.add(sf)
            db.session.commit()
            return jsonify({'id': sf.id, 'name': sf.name, 'params': sf.params})
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Filter save error: {str(e)}")
            return jsonify({'error': 'Failed to save filter'}), 500
    
    saved = SavedFilter.query.filter_by(user_id=current_user.id)\
        .order_by(SavedFilter.created_at.desc()).all()
    return jsonify([{'id': s.id, 'name': s.name, 'params': s.params} for s in saved])

@bp.route('/filters/<int:fid>', methods=['DELETE'])
@login_required
def delete_filter(fid):
    sf = SavedFilter.query.filter_by(id=fid, user_id=current_user.id).first_or_404()
    try:
        db.session.delete(sf)
        db.session.commit()
        return jsonify({'status': 'ok'})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Filter delete error: {str(e)}")
        return jsonify({'error': 'Failed to delete filter'}), 500

@bp.route('/preview/<path:filename>')
@login_required
def preview(filename):
    task = Task.query.filter(
        (Task.document_path == filename) | (Task.confirmation_files.contains([filename]))
    ).first()
    
    if not task:
        flash('File not found.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if current_user.id != task.assigned_to_id and not is_admin():
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    folder = current_app.config['CONFIRMATION_FOLDER'] if filename in (task.confirmation_files or []) \
             else current_app.config['UPLOAD_FOLDER']
    
    return send_from_directory(folder, filename, as_attachment=False)

@bp.route('/export/tasks.csv')
@login_required
def export_tasks_csv():
    if not is_admin():
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    rows = db.session.query(Task.id, Task.title, Task.status, Task.validated, Task.timestamp)\
        .order_by(Task.timestamp.desc()).all()
    
    def generate():
        yield 'id,title,status,validated,created_at\n'
        for r in rows:
            yield f'{r.id},"{r.title}",{r.status},{"yes" if r.validated else "no"},{r.timestamp.isoformat()}\n'
    
    return Response(generate(), mimetype='text/csv', 
                   headers={'Content-Disposition': 'attachment; filename=tasks.csv'})

@bp.route('/notifications/history')
@login_required
def notifications_history():
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).limit(50).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    
    return jsonify({
        'unread_count': unread_count,
        'items': [{
            'id': n.id,
            'message': n.message,
            'task_id': n.task_id,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat()
        } for n in notifications]
    })

@bp.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def notifications_mark_all_read():
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False)\
            .update({Notification.is_read: True})
        db.session.commit()
        return jsonify({'status': 'ok'})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Mark read error: {str(e)}")
        return jsonify({'error': 'Failed to mark as read'}), 500

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))