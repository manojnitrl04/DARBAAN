from django import forms
from .models import s_society_user_auth
from django.core.mail import send_mail
from django.conf import settings
import random
from django.core.mail import EmailMessage

class UserSignupForm(forms.ModelForm):
    class Meta:
        model = s_society_user_auth
        fields = ['user_email_id', 'user_mobile_number']

    # def clean(self):
    #     cleaned_data = super().clean()
    #     password = cleaned_data.get("password")
    #     confirm_password = cleaned_data.get("confirm_password")
    #     if password != confirm_password:
    #         raise forms.ValidationError(
    #             "Passwords do not match"
    #         )
    def send_verification_email(self):
        user_email_id= self.cleaned_data.get('user_email_id')
        #user_mobile_number=self.cleaned_data.get('user_mobile_number')
        otp = random.randint(100001, 999999)

        subject = 'Login OTP'
        message = f'Hi {user_email_id}, Your otp to login is {otp}'
        # body = EmailMessage(message, self.otp, c +d, to=[member_email])
        email_from = settings.EMAIL_HOST_USER
        recipients = [user_email_id, ]
        email_body = EmailMessage(subject, message, email_from, to=recipients)
        email_body.send()
        #request.session['username'] = user_email_id






from django import forms
from .models import s_sms_admin_user_auth

class SignUpForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        model = s_sms_admin_user_auth
        fields = ['admin_role', 'admin_email_id', 'admin_mobile_number', 'password']



from django import forms

class ExcelUploadForm(forms.Form):
    excel_file = forms.FileField()


from django import forms

class SocietyUploadForm(forms.Form):
    excel_file = forms.FileField(label='Excel File', help_text='Please upload an Excel file with society data.')

from django import forms
from django.contrib.auth.forms import PasswordChangeForm


class ChangePasswordForm(PasswordChangeForm):
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )