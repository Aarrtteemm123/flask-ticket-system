from enum import Enum


class TicketStatus(str, Enum):
    PENDING = 'Pending'
    IN_REVIEW = 'In review'
    CLOSED = 'Closed'
