from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])
    submit = SubmitField('Register')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    document = FileField('Upload Document', validators=[FileAllowed(['pdf', 'doc', 'docx'], 'Documents only!')])
    assigned_to = SelectField('Assign To', coerce=int)
    submit = SubmitField('Create Task')

class StatusForm(FlaskForm):
    status = SelectField('Status', choices=[('Not Started', 'Not Started'), ('Started', 'Started'), ('In Progress', 'In Progress'), ('Completed', 'Completed')])
    confirmation_file = FileField('Upload Confirmation File', validators=[FileAllowed(['pdf', 'doc', 'docx'], 'Documents only!')])
    submit = SubmitField('Update Status')

class ValidationForm(FlaskForm):
    submit = SubmitField('Validate Task')