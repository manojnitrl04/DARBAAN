from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from .models import s_sms_admin_user_auth, s_society_user_auth, s_society_master, s_society_association_master


admin.site.register(s_society_user_auth)
admin.site.register(s_society_master)
admin.site.register(s_society_association_master)

from django.contrib.auth.hashers import make_password
from .models import s_sms_admin_user_auth


@admin.register(s_sms_admin_user_auth)
class AdminUserAuth(admin.ModelAdmin):
    exclude = ('last_login',)




# # class s_sms_admin_user_authAdmin(admin.ModelAdmin):
# #     def save_model(self, request, obj, form, change):
# #         obj.password = make_password(obj.password) # Encrypt the password before saving
# #         super().save_model(request, obj, form, change)
