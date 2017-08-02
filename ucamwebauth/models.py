
from django.contrib.auth.models import User
from django.db import models


class UserProfile(models.Model):
    """
    The purpose is this model is to customise the User modal as per the recommendation in
    https://docs.djangoproject.com/en/1.11/topics/auth/customizing/.
    Currently the only addition field is whether or not the user is a "Raven For Life" user,
    ie has left the University but still has access to certain resources.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    raven_for_life = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user)
