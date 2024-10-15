from rest_framework.permissions import BasePermission, IsAdminUser,IsAuthenticated

class IsUserorAdmin(BasePermission):
	def has_permission(self, request, view):
		return  IsAuthenticated().has_permission(request, view)
	def has_object_permission(self, request, view, obj):
		return IsAdminUser().has_permission(request, view) or obj.user == request.user

class IsOwner(BasePermission):
	def has_permission(self, request, view):
		return  IsAuthenticated().has_permission(request, view)
	def has_object_permission(self, request, view, obj):
		return IsAdminUser().has_permission(request, view) or obj == request.user


class IsNotUser(BasePermission):
	def has_permission(self, request, view):
		if IsAuthenticated().has_permission(request, view):
			return False
		else:
			return True
	def has_object_permission(self, request, view, obj):
		if IsAuthenticated().has_permission(request, view):
			return False
		else:
			return True