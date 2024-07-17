from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin

from app.roles import UserRole
from app.ticket_status import TicketStatus


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)

    # @staticmethod
    # def validate_role(role):
    #     valid_roles = [role.value for role in UserRole]
    #     if role not in valid_roles:
    #         raise ValueError(f"Invalid role. Valid roles are: {', '.join(valid_roles)}")


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    users = db.relationship('User', backref='group', lazy=True)
    tickets = db.relationship('Ticket', backref='group', lazy=True)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(30), default=TicketStatus.PENDING.value, nullable=False)
    note = db.Column(db.Text, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    assigned_user = db.relationship('User', foreign_keys=[assigned_user_id])
