from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
from django.shortcuts import render,redirect,get_object_or_404
from django.contrib.auth.decorators import login_required
from .serializers import UserSerializer, TodoSerializer
from rest_framework.decorators import action,api_view
from django.contrib.auth import login,authenticate
from django.contrib.sessions.models import Session
from rest_framework import permissions,generics
from.permission import IsUserorAdmin,IsNotUser,IsOwner
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import JsonResponse
from rest_framework import viewsets
from .form import UserCreationForm
from django.conf import settings
from .models import todo
import random
import string

#View sets for api
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    def get_permissions(self):
        if self.action == "create":
            self.permission_classes = [IsNotUser]
        else:
            self.permission_classes = [IsOwner]
        return super().get_permissions()
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "User deleted successfully","status": 200})


class todoViewSet(viewsets.ModelViewSet):
    queryset = todo.objects.all()
    serializer_class = TodoSerializer
    permission_classes = [IsUserorAdmin,permissions.IsAuthenticated]
    @action(detail=True, methods=['get'])
    def todos(self, request, pk=None):
        user = get_object_or_404(User, pk=pk)
        todos = todo.objects.filter(user=user)
        todo_serializer = TodoSerializer(todos, many=True, context={'request': request})
        data = {
            'todos': todo_serializer.data,
            'count': todos.count(),
            "status":200
            }
        return Response(data)
    def create(self, request, *args, **kwargs):
        # Automatically assign the current user to the new todo
        request.data['user'] = f"http://127.0.0.1:8000/api/users/{request.user.id}/"
        # request.data['user'] = f"https://skytodo.pythonanywhere.com/api/users/{request.user.id}/"
        return super().create(request, *args, **kwargs)
    def update(self, request, *args, **kwargs):
        request.data['user'] = f"http://127.0.0.1:8000/api/users/{request.user.id}/"
        # request.data['user'] = f"https://skytodo.pythonanywhere.com/api/users/{request.user.id}/"
        return super().update(request, *args, **kwargs)


class LoginView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")
        print(email, password)
        username = User.objects.get(email=email).username
        user = authenticate(username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            data = {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'message': "Log-in Successful",
                'status':200
            }
            return Response(data)
    
        return Response({'message': "Invalid credentials","status":401}, status=401)

class logoutview(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        return Response({'message': "Log-out Successful","status":200})
        
# function for registration

@api_view(['POST'])
def otpverificationView(request):
    try:
        session = Session.objects.get(session_key=request.data.get('session_key'))
        session_data = session.get_decoded()
        otp = request.data.get('otp')

        if session_data.get('otp') != otp:
            return Response({"message": "Wrong OTP","status":400})

        user = User(username=session_data['username'], email=session_data['email'])
        user.set_password(session_data['password'])
        user.save()
        session.delete()

        refresh = RefreshToken.for_user(user)
        return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'message': "User created successfully!",
                "status":200
        })

    except Session.DoesNotExist:
        return Response({"message": "Invalid session key"}, status=400)
@api_view(['POST'])
def registrationView(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    if len(password) < 8:
        return Response({"message": "Password must be at least 8 characters long","status":400})
    verification = checkuser(request.data)
    if verification['response']:
        return Response({"message": verification['message'],"status":200})

    # Store user data in session and generate OTP
    session = request.session
    session['username'] = username
    session['email'] = email
    session['password'] = password
    session.save()
    message = 'Registration otp '
    otp_response = generate_otp(email,message)
    
    session['otp'] = otp_response['otp']

    request.session.set_expiry(300)
    key = session.session_key
    print(key)
    request.session.save()
    data = {"message": otp_response['message'], "session_key":key,"status":200}
    return Response(data)

@api_view(['POST'])
def forgotpasswordView(request):
    email = request.data.get('email')
    verification = checkuser(request.data)
    if not verification['response']:
        return Response({"message": verification['message'],"status":400})
    message = 'Password reset otp '
    otp_response = generate_otp(email,message)
    session = request.session
    session['otp'] = otp_response['otp']
    session['email'] = email
    session.set_expiry(1000)
    session.save()
    key = request.session.session_key
    data = {"message": otp_response['message'],"session_key":key,"status":200}
    return Response(data)

@api_view(['POST'])
def changepasswordView(request):
    session_key = request.data.get('session_key')
    print(request.data)
    session = None
    try:
        session = get_object_or_404(Session, session_key=session_key)
        session_data = session.get_decoded()
        otp = request.data.get('otp')
        email = session_data.get('email')
        password = request.data.get('password')
        if password is None:
            return Response({"message": "Password cannot be empty","status":400})
        if otp == session_data.get('otp'):
            user = get_object_or_404(User, email=email)
            user.set_password(password)
            user.save()
            request.session.delete()
            return Response({"message": "Password changed successfully!","status":200})
    except Exception as e:
        return Response({"message": f'Error: {e}',"status":400},)
def checkuser(data):
    user = None
    try:
        user = get_object_or_404(User,username = data['username'])
    except Exception as error:
        pass
    if user:
        message = {"response":True,"message":'User already exist'}
        return message
    try:
        user = get_object_or_404(User,email=data['email'])
    except Exception as error:
        pass
    if user:
        message = {"response":True,"message":"Email already in use"}
        return message
    message = {"response":False,"message":"User does not exist"}
    return message	

def generate_otp(email,message):
    otp = ''.join(random.choices(string.digits, k=6))
    subject = 'Your OTP Code'
    message = f'{message}: {otp}'
    from_email = settings.DEFAULT_FROM_EMAIL
    if otp:
        send_mail(subject, message, from_email, [email])
        return {f'message': 'OTP resent successfully!','otp':int(otp)}
    else:
        return {'message': 'No OTP found in session.',"otp" :None }
