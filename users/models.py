from django.db import models

# Create your models here.


class User(models.Model):
    email = models.EmailField(max_length=200)
    id_token = models.JSONField()

    def __str__(self) -> str:
        return "%s: %s" % (self.email, self.id_token)
