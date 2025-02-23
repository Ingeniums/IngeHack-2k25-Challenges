from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class Quote(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE) 
    text = models.TextField()  
    private = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return f'"{self.text}" - {self.author}'