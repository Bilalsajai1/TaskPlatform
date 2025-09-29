from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), default='user')  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relations
    tasks = db.relationship('Task', backref='assignee', lazy='dynamic', 
                          foreign_keys='Task.assigned_to_id')
    created_tasks = db.relationship('Task', backref='creator', lazy='dynamic', 
                                   foreign_keys='Task.created_by_id')
    comments = db.relationship('Comment', backref='user', lazy='dynamic')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')
    saved_filters = db.relationship('SavedFilter', backref='user', lazy='dynamic')
    
    def __repr__(self):
        return f"<User {self.username}>"

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text)
    document_path = db.Column(db.String(200))  # Original document
    confirmation_files = db.Column(db.JSON, default=list)  # List of confirmation file paths
    status = db.Column(db.String(20), default='Not Started', index=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    validated = db.Column(db.Boolean, default=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    due_date = db.Column(db.DateTime, index=True)
    priority = db.Column(db.String(10), default='Normal')  # Low, Normal, High
    tags = db.Column(db.JSON, default=list)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relations
    comments = db.relationship('Comment', backref='task', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='task', lazy='dynamic')
    
    def __repr__(self):
        return f"<Task {self.title}>"
    
    @property
    def is_overdue(self):
        """Vérifie si la tâche est en retard"""
        if self.due_date and not self.validated:
            return datetime.utcnow() > self.due_date
        return False
    
    @property
    def status_badge_class(self):
        """Retourne la classe Bootstrap pour le badge de statut"""
        status_map = {
            'Not Started': 'secondary',
            'Started': 'warning',
            'In Progress': 'info',
            'Completed': 'success'
        }
        return status_map.get(self.status, 'secondary')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Comment on Task {self.task_id}>"

class SavedFilter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    params = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<SavedFilter {self.name}>"

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    message = db.Column(db.String(255), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), index=True)
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<Notification for User {self.user_id}>"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))