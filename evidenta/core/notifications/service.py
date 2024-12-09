from evidenta.core.notifications.enums import NotificationScheduleType, NotificationTemplateType, NotificationType
from evidenta.core.user.models import User


class NotificationService:
    def _send_notification(
        self,
        notification_type: NotificationType,
        template: NotificationTemplateType,
        schedule: NotificationScheduleType,
        **kwargs,
    ):
        """
        Prozatim reseno printem. Az bude existovat notifikacni servisa, tak se tu prida
        task do fronty, kterou bude tato servisa zpracovavat.
        """
        print(  # noqa: T201
            f"[Notification task] notification type: {notification_type} template: {template} "
            f"schedule: {schedule} kwargs: {kwargs}"
        )

    def send_invitation_link(self, user: User, link: str) -> None:
        # todo: pridat moznost naplanovat odeslani invitu
        self._send_notification(
            notification_type=NotificationType.EMAIL,
            template=NotificationTemplateType.INVITE_MESSAGE,
            schedule=NotificationScheduleType.NOW,
            user=user,
            link=link,
        )

    def send_update_password_otp(self, user: User, otp: str) -> None:
        self._send_notification(
            notification_type=NotificationType.EMAIL,
            template=NotificationTemplateType.UPDATE_PASSWORD,
            schedule=NotificationScheduleType.NOW,
            user=user,
            otp=otp,
        )

    def send_reset_password_link(self, user: User, link: str) -> None:
        self._send_notification(
            notification_type=NotificationType.EMAIL,
            template=NotificationTemplateType.RESET_PASSWORD,
            schedule=NotificationScheduleType.NOW,
            user=user,
            link=link,
        )
