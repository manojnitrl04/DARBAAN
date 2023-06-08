from collections import UserDict
import datetime
from email.message import EmailMessage
from json import JSONDecodeError
import json
import random
import bcrypt
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from requests import Response
import requests
from rest_framework.decorators import api_view
from rest_framework import viewsets
from .models import s_society_user_auth
from .serializers import UserSerializer
from .models import s_sms_admin_user_auth
from .serializers import AdminUserSerializer
from .serializers import SocietyAssociationMasterSerializer
from .models import s_society_association_master
from .serializers import SocietyMasterSerializer
from .models import s_society_master
from django.core.mail import EmailMessage
from django.conf import settings
import random
from django.contrib.auth import update_session_auth_hash
from rest_framework.response import Response
from .models import s_society_staff_master,s_society_flat_master,s_society_flat_residential_status
from .serializers import SocietyStaffSerializer,SocietyresidentialSerializer,Societyflatserializer
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from .models import s_society_master, s_society_user_auth, s_society_association_master


class UserViewSet(viewsets.ModelViewSet):
    queryset = s_society_user_auth.objects.all()
    serializer_class = UserSerializer


class AdminUserViewSet(viewsets.ModelViewSet):
    queryset = s_sms_admin_user_auth.objects.all()
    serializer_class = AdminUserSerializer


class SocietyMasterViewSet(viewsets.ModelViewSet):
    queryset = s_society_master.objects.all()
    serializer_class = SocietyMasterSerializer


class SocietyAssociationMasterViewSet(viewsets.ModelViewSet):
    queryset = s_society_association_master.objects.all()
    serializer_class = SocietyAssociationMasterSerializer

class SocietyStaffViewSet(viewsets.ModelViewSet):
    queryset = s_society_staff_master.objects.all()
    serializer_class = SocietyStaffSerializer

class SocietyResidentialViewSet(viewsets.ModelViewSet):
    queryset = s_society_flat_residential_status.objects.all()
    serializer_class = SocietyresidentialSerializer


class SocietyFlatViewSet(viewsets.ModelViewSet):
    queryset = s_society_flat_master.objects.all()
    serializer_class = Societyflatserializer

#internal user login
@csrf_exempt
@api_view(['POST'])
def admin_login(request):
    if request.method == 'POST':
        email = request.data.get('admin_email_id')
        password = request.data.get('password')

       
        try:
            user = s_sms_admin_user_auth.objects.get(admin_email_id=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                if user.last_login is None:
                    # User is logging in for the first time, force password change
                    return JsonResponse(
                        {'status': '1', 'message': 'Please change your password.'})
                else:
                    user.last_login = datetime.datetime.now()
                    # user.save()
                    return JsonResponse({'status': '0', 'message': 'Login successful!'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid password!'})
        except s_sms_admin_user_auth.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found!'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method!'})

@csrf_exempt
@api_view(['POST'])
def admin_firsttime_password_change_request(request):
    if request.method == 'POST':
        email = request.POST.get('admin_email_id')
        password = request.POST.get('password')
        try:
            user = s_sms_admin_user_auth.objects.get(admin_email_id=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                if user.last_login is None:
                    # User is logging in for the first time, force password change
                    return JsonResponse(
                        {'status': '1', 'message': 'Please change your password.'})
                else:
                    user.last_login = datetime.datetime.now()
                    user.save()
                    return JsonResponse({'status': '0', 'message': 'Login successful!'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid password!'})
        except s_sms_admin_user_auth.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found!'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method!'})
    



from django.http import HttpRequest

@api_view(['POST'])
def admin_change_password_request(request):
    if isinstance(request._request, HttpRequest):
        # Extract the HttpRequest object from the Request object
        http_request = request._request

        if http_request.method == 'POST':
            email = http_request.POST.get('admin_email_id')
            current_password = http_request.POST.get('current_password')
            new_password = http_request.POST.get('new_password')
            confirm_password = http_request.POST.get('confirm_password')

            try:
                user = s_sms_admin_user_auth.objects.get(admin_email_id=email)

                if bcrypt.checkpw(current_password.encode('utf-8'), user.password.encode('utf-8')):
                    if new_password == confirm_password:
                        # Hash the new password using bcrypt and update the user's password
                        #hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                        user.password = new_password
                        user.password_changed = True
                        user.last_login = datetime.datetime.now()

                        # Update the user's session
                        update_session_auth_hash(http_request, user)
                        user.save()

                        return JsonResponse({'status': '1', 'message': 'Password changed successfully!'})
                    else:
                        return JsonResponse({'status': '0', 'message': 'Passwords do not match!'})
                else:
                    return JsonResponse({'status': 'error', 'message': 'Incorrect current password!'})
            except s_sms_admin_user_auth.DoesNotExist:
                return JsonResponse({'status': '2', 'message': 'User not found!'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid request method!'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request object type!'})


#code which are working
#External users login
@csrf_exempt
@api_view(['POST'])
def user_login(request):
    if request.method == 'POST':
        user_email_id = request.data.get('user_email_id')
        member = s_society_user_auth.objects.filter(user_email_id=user_email_id)
        if not member.exists():
            context = {'message': 'User not found', 'class': 'danger'}
            return JsonResponse(context, status=400)

        otp = str(random.randint(100000, 999999))
        member.update(log_otp=otp)

        subject = 'Login OTP'
        message = f'Hi {user_email_id}, Your OTP to login is {otp}'
        email_from = settings.EMAIL_HOST_USER
        recipients = [user_email_id]
        email_body = EmailMessage(subject, message, email_from, to=recipients)
        email_body.send()

        # Start a new thread to delete the OTP after a delay
        thread = threading.Thread(target=delete_otp_after_delay, args=(user_email_id,))
        thread.start()

        return JsonResponse({'message': 'OTP sent successfully!', 'otp': otp})

    return JsonResponse({'message': 'Invalid request method'}, status=400)


def delete_otp_after_delay(user_email_id):
    time.sleep(180)  # Wait for 3 minutes
    member = s_society_user_auth.objects.filter(user_email_id=user_email_id)
    member.update(log_otp='')


@csrf_exempt
@api_view(['POST'])
def user_login_otp_verify(request):
    if request.method == 'POST':
        user_email_id = request.data.get('user_email_id')
        otp = request.data.get('otp')

        try:
            user = s_society_user_auth.objects.get(user_email_id=user_email_id)
            if str(user.log_otp) == otp:
                # If OTP is verified, set user as authenticated and return a success response
                success_message = f"OTP verified successfully! Logged in as {user_email_id}."
                user.log_otp = None  # Set log_otp to None (or an empty string if needed)
                user.save()
                return JsonResponse({'message': success_message})
            else:
                # If OTP is invalid, return an error response
                context = {'message': 'Invalid OTP', 'class': 'danger'}
                return JsonResponse(context, status=400)
        except s_society_user_auth.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=400)

    # If request method is not POST, return an error response
    return JsonResponse({'message': 'Invalid request method'}, status=400)




#external users signup
# logout function
from django.contrib.auth import logout
from django.http import JsonResponse    
@csrf_exempt
@api_view(['GET'])
def logout_view(request):
    logout(request)
    return JsonResponse({"message": "Logged out successfully"})

# update soceity delt src indicator

from django.http import JsonResponse

@csrf_exempt
@api_view(['POST'])
def update_society_inactive(request, soc_id):
    if request.method == 'POST':
        try:
            society = s_society_master.objects.get(soc_id=soc_id)
            society.deld_in_src_ind = 'yes'
            society.save()
            return JsonResponse({'message': 'Society updated successfully'})
        except s_society_master.DoesNotExist:
            return JsonResponse({'message': 'Society not found'}, status=404)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)




# this API will inactivate society from society master and related records from association master
@csrf_exempt
@api_view(['POST'])
def inactivate_society(request, soc_id):
    if request.method == 'POST':
        try:
            society = s_society_master.objects.get(soc_id=soc_id)
            society.deld_in_src_ind = 'yes'
            society.save()

            # Update associated records in s_society_association_master
            association_records = s_society_association_master.objects.filter(soc_id=soc_id)
            association_records.update(deld_in_src_ind='yes')

            return JsonResponse({'message': 'Society and associated records updated successfully'})
        except s_society_master.DoesNotExist:
            return JsonResponse({'message': 'Society not found'}, status=404)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)
    


# this API will inactivate the user account  and the related records from association master
@csrf_exempt
@api_view(['POST'])
def inactivate_user(request, user_key):
    if request.method == 'POST':
        try:
            user_auth = s_society_user_auth.objects.get(user_key=user_key)
            user_auth.deld_in_src_ind = 'yes'
            user_auth.save()

            # Update associated record in s_society_association_master
            association_record = s_society_association_master.objects.get(member_email_id=user_auth.user_email_id)
            association_record.deld_in_src_ind = 'yes'
            association_record.save()

            return JsonResponse({'message': 'User and associated record updated successfully'})
        except s_society_user_auth.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except s_society_association_master.DoesNotExist:
            return JsonResponse({'message': 'Associated record not found'}, status=404)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)
    


# update email id phone number and dates of society master
@csrf_exempt
@api_view(['POST'])
def update_society2(request, soc_key):
    if request.method == 'POST':
        try:
            society = s_society_master.objects.get(soc_key=soc_key)
            society.email_id = request.data.get('email_id', society.email_id)
            society.contact_num = request.data.get('contact_num', society.contact_num)
            society.eff_frm_dt = request.data.get('eff_frm_dt', society.eff_frm_dt)
            society.eff_to_dt = request.data.get('eff_to_dt', society.eff_to_dt)


            society.save()

            return JsonResponse({'message': 'Society details updated successfully'})
        except s_society_master.DoesNotExist:
            return JsonResponse({'message': 'Society not found'}, status=404)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)



    #signup fuction  
    

def send_email_otp(user_email_id):
    otp = str(random.randint(100000, 999999))
    subject = 'signup OTP'
    message = f'Hi {user_email_id}, your OTP to signup is {otp}'
    email_from = settings.EMAIL_HOST_USER
    recipients = [user_email_id]
    email = EmailMessage(subject, message, email_from, recipients)
    email.send()

    return otp



def send_mobile_otp(user_mobile_number):
    otp = random.randint(1000, 999999)
    otp_str = str(otp).zfill(6)[:6]  # ensure OTP is between 4 to 6 digits
    url = url = f"https://2factor.in/API/V1/61be8913-fedd-11ed-addf-0200cd936042/SMS/{user_mobile_number}/{otp_str}/AUTOGEN"
    response = requests.post(url)

    # Debugging code: print response content and status code
    print(response.content)
    print(response.status_code)

    try:
        response_data = response.json()
    except JSONDecodeError as e:
        return f"Error sending OTP: {e}"

    if response.status_code == 200 and response_data["Status"] == "Success":
        return otp_str
    else:
        return f"Error sending OTP: {response_data['Details']}"
    

    
    
import threading
import time
from django.http import HttpResponse

@csrf_exempt
@api_view(['POST'])
def user_signup_form(request):
    if request.method == 'POST':
        user_email = request.data.get('user_email_id')
        user_mobile_number = request.data.get('user_mobile_number')
        username = request.data.get('username')

        email_otp = send_email_otp(user_email)
        mobile_otp = send_mobile_otp(user_mobile_number)

        user = s_society_user_auth.objects.create(
            user_email_id=user_email,
            user_mobile_number=user_mobile_number,
            username=username,
            email_otp=email_otp,
            mobile_otp=mobile_otp,
            email_id_verified=False,
            mobile_no_verified=False
        )
        user.save()

        # Start a new thread to check verification status and delete the user record if necessary
        thread = threading.Thread(target=check_and_delete_user_record, args=(user.user_key,))
        thread.start()

        return Response({'message': 'Email and Mobile OTPs sent successfully'})

def check_and_delete_user_record(user_key):
    time.sleep(180)  # Wait for 3 minutes
    try:
        user = s_society_user_auth.objects.get(user_key=user_key)
        if not user.email_id_verified or not user.mobile_no_verified:
            user.delete()  # Delete the user record if verification is not completed
            return True  # Indicate that the deletion was successful
    except s_society_user_auth.DoesNotExist:
        pass

    return False  # Indicate that the user record was not found or verification was completed

@csrf_exempt
@api_view(['POST'])
def user_signup_email_mobile_verify(request):
    user_email = request.data.get('user_email_id')
    user_mobile_number = request.data.get('user_mobile_number')
    email_otp = request.data.get('email_otp')
    mobile_otp = request.data.get('mobile_otp')

    try:
        user = s_society_user_auth.objects.get(user_email_id=user_email, user_mobile_number=user_mobile_number)
        if str(user.email_otp) == email_otp and str(user.mobile_otp) == mobile_otp:
            user.email_id_verified = True
            user.mobile_no_verified = True
            user.save()
            return Response({'message': 'Email and mobile verification successful'})
        else:
            return Response({'message': 'Invalid OTPs'})
    except s_society_user_auth.DoesNotExist:
        return Response({'message': 'User not found'})



        # views.py

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
@csrf_exempt
@login_required     
def get_logged_in_user_name(request):
    user = request.user
    name = user.username  # Assuming the username is used as the name
    
    return JsonResponse({'name': name})
