from enum import Enum


class UserRole(str, Enum):
    ADMIN = 'Admin'
    MANAGER = 'Manager'
    ANALYST = 'Analyst'
