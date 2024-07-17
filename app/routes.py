from operator import or_

from flask import render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required

from app import db
from app.decorators import roles_required
from app.models import User, Group, Ticket
from app.forms import LoginForm, TicketForm, RegistrationForm, GroupForm, UserForm
from werkzeug.security import generate_password_hash, check_password_hash

from app.roles import UserRole

bp = Blueprint('main', __name__)


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data,
            group_id=form.group.data if form.role.data != UserRole.ADMIN else None
        )
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='Register', form=form)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@bp.route('/dashboard')
@login_required
@roles_required(UserRole.ADMIN, UserRole.MANAGER, UserRole.ANALYST)
def dashboard():
    if current_user.role == UserRole.ADMIN:
        tickets = Ticket.query.all()
    else:
        query = [Ticket.assigned_user_id == current_user.id]
        if current_user.group_id:
            query.append(Ticket.group_id == current_user.group_id)
        tickets = Ticket.query.filter(or_(*query)).all()
    return render_template('dashboard.html', tickets=tickets)


@bp.route('/ticket/new', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.MANAGER)
def new_ticket():
    form = TicketForm(user=current_user)
    if form.validate_on_submit():
        ticket = Ticket(
            note=form.note.data,
            group_id=form.group.data or None,
            status=form.status.data,
            assigned_user_id=form.assigned_user.data or None
        )
        db.session.add(ticket)
        db.session.commit()
        flash('Your ticket has been created!', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('create_ticket.html', title='New Ticket', form=form)


@bp.route('/ticket/<int:ticket_id>')
@login_required
@roles_required(UserRole.ADMIN, UserRole.MANAGER, UserRole.ANALYST)
def ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    return render_template('ticket_detail.html', title=ticket.id, ticket=ticket)


@bp.route('/ticket/<int:ticket_id>/update', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.MANAGER, UserRole.ANALYST)
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role != UserRole.ADMIN and (not current_user.group_id or current_user.group_id != ticket.group_id):
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('main.dashboard'))

    form = TicketForm()
    if form.validate_on_submit():
        ticket.note = form.note.data
        if current_user.role == UserRole.ADMIN:
            ticket.group_id = form.group.data or None
            ticket.assigned_user_id = form.assigned_user.data or None
        ticket.status = form.status.data
        db.session.commit()
        flash('Your ticket has been updated!', 'success')
        return redirect(url_for('main.ticket', ticket_id=ticket.id))
    elif request.method == 'GET':
        form.note.data = ticket.note
        form.group.data = ticket.group_id
        form.status.data = ticket.status
        form.assigned_user.data = ticket.assigned_user_id
    return render_template('update_ticket.html', title='Update Ticket', form=form, ticket=ticket)


@bp.route('/manage_groups')
@login_required
@roles_required(UserRole.ADMIN)
def manage_groups():
    groups = Group.query.all()
    return render_template('manage_groups.html', groups=groups)


@bp.route('/create_group', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN)
def create_group():
    form = GroupForm()
    if form.validate_on_submit():
        group = Group(name=form.name.data)
        db.session.add(group)
        db.session.commit()
        flash('New group has been created!', 'success')
        return redirect(url_for('main.manage_groups'))
    return render_template('create_group.html', title='Create Group', form=form)


@bp.route('/users')
@login_required
@roles_required(UserRole.ADMIN)
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)


@bp.route('/user/new', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN)
def new_user():
    form = UserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data) if form.password.data else None
        user = User(username=form.username.data, email=form.email.data, role=form.role.data,
                    group_id=form.group.data or None, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('New user has been created!', 'success')
        return redirect(url_for('main.manage_users'))
    return render_template('create_user.html', title='Create User', form=form)


@bp.route('/user/<int:user_id>/update', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN)
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm()
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.role.data
        user.group_id = form.group.data or None
        if form.password.data:
            user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('User details have been updated!', 'success')
        return redirect(url_for('main.manage_users'))
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.role.data = user.role
        form.group.data = user.group_id or 0
    return render_template('update_user.html', title='Update User', form=form, user=user)


@bp.route('/ticket/<int:ticket_id>/delete', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.MANAGER)
def delete_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    db.session.delete(ticket)
    db.session.commit()
    flash('The ticket has been deleted!', 'success')
    return redirect(url_for('main.dashboard'))


@bp.route('/group/<int:group_id>/delete', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN)
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)
    db.session.delete(group)
    db.session.commit()
    flash('The group has been deleted!', 'success')
    return redirect(url_for('main.manage_groups'))


@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN)
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('The user has been deleted!', 'success')
    return redirect(url_for('main.manage_users'))
