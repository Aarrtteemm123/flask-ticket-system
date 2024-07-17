from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user
from app.roles import UserRole


def roles_required(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapper_function(*args, **kwargs):
            all_roles = [role for role in UserRole]
            roles_str = [role.value for role in roles]
            if current_user.role not in roles_str:
                flash(f'You do not have permission to access this page. Required roles: {", ".join(all_roles)}', 'danger')
                return redirect(url_for('main.login'))
            return f(*args, **kwargs)
        return wrapper_function
    return wrapper
