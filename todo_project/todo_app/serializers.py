from rest_framework.serializers import *
from django.core.validators import MaxLengthValidator
from django.contrib.auth.models import User
from .validator import ImageValidator
from .models import todo
class UserSerializer(ModelSerializer):
    email = EmailField(required=True)
    class Meta:
        model = User
        fields = ['id', 'username', 'password','email']
        extra_kwargs = {'password': {'write_only': True}}
    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user
class TodoSerializer(HyperlinkedModelSerializer):
    id = ReadOnlyField()
    created_at = ReadOnlyField()
    class Meta:
        model = todo
        fields = ['user', 'img', 'text','id','created_at']

    def validate_img(self, value):
        print('validating img')
        print(value)
        if value:
            print("sending img")
            imgvalidator = ImageValidator()
            imgvalidator(value)
            
        return value
    
    def validate_text(self, value):
        max_length_validator = MaxLengthValidator(limit_value=100)
        try:
            max_length_validator(value)
        except ValidationError as e:
            raise ValidationError(f"Text exceeds maximum length of 100 characters. {str(e)}")
        return value