"""
URL configuration for todo_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib.auth.urls import views as auth_views
from django.conf.urls.static import static
from django.urls import path ,include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views
from django.conf import settings
router = routers.DefaultRouter() # assign router
router.register(r'users', views.UserViewSet)
router.register(r'todo', views.todoViewSet)

urlpatterns = [
	path('api/', include(router.urls)),
	# path('',views.home,name='home'),
	path('otp/',views.generate_otp,name='otp'),
    # path('login/', auth_views.LoginView.as_view(), name='login'),
    # path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    # path('register/', views.register, name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.logoutview.as_view(), name='logout'),
    path('register/', views.registrationView, name='register'),
    path('check_otp/', views.otpverificationView, name='check_otp'),
    path('forgot_password/', views.forgotpasswordView, name='forgot_password'),
    path('change_password/', views.changepasswordView, name='change_password'),
	path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
	path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
	path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]+static(settings.MEDIA_URL,document_root = settings.MEDIA_ROOT)
