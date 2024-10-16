from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class todo(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	img = models.ImageField( upload_to="media",null = True,blank = True)
	text =  models.CharField( max_length=1000,null = True,blank = True)
	created_at = models.DateTimeField(auto_now_add=True)
	id = models.AutoField(primary_key= True)
	def __str__(self):
		return f'todo {self.id}'