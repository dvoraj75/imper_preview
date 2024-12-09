from enum import Enum, auto


class NotificationType(Enum):
    EMAIL = auto()


class NotificationScheduleType(Enum):
    NOW = auto()
    SCHEDULED = auto()


class NotificationTemplateType(Enum):
    INVITE_MESSAGE = auto()
    UPDATE_PASSWORD = auto()
    RESET_PASSWORD = auto()
