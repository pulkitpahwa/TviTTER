from django.db import models
from django.contrib.auth.models import User

class FueledUser(models.Model):
    name     = models.CharField(max_length = 100, blank = True, null = True)
    twitter_username = models.CharField(max_length = 50, blank = True, null = True)
    oauth_token = models.CharField(max_length = 20, blank = True, null = True)
    oauth_token_secret = models.CharField(max_length = 50, blank = True, null = True)
    oauth_verifier = models.CharField(max_length= 20,  blank = True, null = True)


    def __unicode__(self) : 
        return self.name
