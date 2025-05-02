from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    """
    email = models.EmailField(_('email address'), unique=True)
    date_joined = models.DateTimeField(_('date joined'), auto_now_add=True)
    
    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        db_table = 'auth_user'
        swappable = 'AUTH_USER_MODEL'

    def __str__(self):
        return self.username 