from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django import forms
class  UserCreationForm(UserCreationForm):
    otp = forms.CharField(min_length= 6,max_length=6, required=True)
    class Meta:
        model = User
        fields= ("username",'email',"password1","password2","otp")