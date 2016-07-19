from django.db import models
# Create your models here.

class ScopeURLSandTests(models.Model):
    MD5=models.CharField(max_length=30)
    SCOPEURLS=models.TextField()
    SCOPETESTS=models.TextField()