from core import views
from django.urls import path,include
from django.contrib.auth import views as auth_views
from django.urls import path
from .views import SocietyMasterViewSet, SocietyAssociationMasterViewSet, update_society2
from django.urls import include, path
from rest_framework import routers
from .views import UserViewSet,AdminUserViewSet,SocietyFlatViewSet, SocietyResidentialViewSet, SocietyStaffViewSet



router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'admin-users', AdminUserViewSet)
router.register(r'society', SocietyMasterViewSet)
router.register(r'association', SocietyAssociationMasterViewSet)
router.register(r'flat',SocietyFlatViewSet)
router.register(r'staff',SocietyStaffViewSet)
router.register(r'residential',SocietyResidentialViewSet)




app_name = 'core'

urlpatterns = [
    path('', include(router.urls)),
    path('api/admin_login/', views.admin_login, name='admin_login'),
    path('api/admin_firsttime_password_change_request/', views.admin_firsttime_password_change_request, name='admin_firsttime_password_change_request'),
    path('api/admin_change_password_request/', views.admin_change_password_request, name='admin_change_password_request'),
    path('api/user_login/', views.user_login, name='user_login'),
    path('api/user_login_otp_verify/', views.user_login_otp_verify, name='user_login_otp_verify'),
    path('api/logout_view/', views.logout_view, name='logout_view'),
    path('api/update_society_inactive/<str:soc_id>/',views.update_society_inactive,name ='update_society_inactive'),
    path('api/inactivate_society/<str:soc_id>/',views.inactivate_society,name ='inactivate_society'),
    path('api/inactivate_user/<int:user_key>/update_user/', views.inactivate_user, name='inactivate_user'),
    path('api/update_society2/<int:soc_key>/',update_society2, name='update_society'),
    path('api/user_signup_form/', views.user_signup_form, name='user_signup_form'),
    path('api/user_signup_email_mobile_verify/', views.user_signup_email_mobile_verify, name='user_signup_email_mobile_verify'),
    path('api/get_logged_in_user_name/', views.get_logged_in_user_name, name='get_logged_in_user_name'),

]


