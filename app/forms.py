from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, ValidationError, Optional
from app.models import User, Group
from app.roles import UserRole
from app.ticket_status import TicketStatus


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class TicketForm(FlaskForm):
    note = TextAreaField('Note', validators=[DataRequired()])
    group = SelectField('Group', coerce=int, default=None, validators=[Optional()])
    status = SelectField('Status', choices=[(status.value, status.value) for status in TicketStatus],
                         default='Pending')
    assigned_user = SelectField('Assign User', coerce=int, default=None, validators=[Optional()])
    submit = SubmitField('Save')

    def __init__(self, user=None, *args, **kwargs):
        super(TicketForm, self).__init__(*args, **kwargs)
        self.group.choices = [(0, 'None')] + [(g.id, g.name) for g in Group.query.all()]
        if user and user.role == UserRole.MANAGER:
            self.assigned_user.choices = [(0, 'None')] + [(u.id, u.username) for u in User.query.filter_by(group_id=user.group_id).all()]
        else:
            self.assigned_user.choices = [(0, 'None')] + [(u.id, u.username) for u in User.query.all()]


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[(role.value, role.value) for role in UserRole],
                       validators=[DataRequired()])
    group = SelectField('Group', coerce=int, validators=[Optional()])
    submit = SubmitField('Register')

    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        self.group.choices = [(0, 'None')] + [(g.id, g.name) for g in Group.query.all()]

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class GroupForm(FlaskForm):
    name = StringField('Group Name', validators=[DataRequired(), Length(min=2, max=50)])
    submit = SubmitField('Create Group')

    def validate_name(self, name):
        group = Group.query.filter_by(name=name.data).first()
        if group:
            raise ValidationError('That group name is taken. Please choose a different one.')


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('Manager', 'Manager'), ('Analyst', 'Analyst')],
                       validators=[DataRequired()])
    group = SelectField('Group', coerce=int, validators=[Optional()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save User')

    def __init__(self, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        self.group.choices = [(0, 'None')] + [(g.id, g.name) for g in Group.query.all()]
