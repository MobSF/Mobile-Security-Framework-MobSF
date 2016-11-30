from django.db import models


class RecentScansDB(models.Model):
    NAME = models.TextField()
    MD5 = models.CharField(max_length=32)
    URL = models.TextField()
    TS = models.DateTimeField()
