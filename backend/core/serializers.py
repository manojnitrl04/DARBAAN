from rest_framework import serializers
from .models import s_society_user_auth, s_sms_admin_user_auth, s_society_master, s_society_association_master
from rest_framework import serializers
from .models import s_society_staff_master,s_society_flat_residential_status,s_society_flat_master


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = s_society_user_auth
        fields = '__all__'


class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = s_sms_admin_user_auth
        fields = '__all__'
    

class SocietyMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = s_society_master
        fields = '__all__'

class SocietyAssociationMasterSerializer(serializers.ModelSerializer):
    member_role=serializers.ListField()
    class Meta:
        model = s_society_association_master
        fields = '__all__'  
       
        


class SocietyStaffSerializer(serializers.ModelSerializer):
    class Meta:
        model = s_society_staff_master
        fields = '__all__'


class SocietyresidentialSerializer(serializers.ModelSerializer):
    class Meta:
        model = s_society_flat_residential_status
        fields = '__all__'




class Societyflatserializer(serializers.ModelSerializer):
    class Meta:
        model = s_society_flat_master
        fields = '__all__'


        

class LoginSerializer(serializers.Serializer):
    user_email_id = serializers.EmailField()


    

class SignupSerializer(serializers.Serializer):
    user_email_id = serializers.EmailField(required=True)
    user_mobile_number = serializers.CharField(required=True)
    username = serializers.CharField(required=True)
    email_otp = serializers.CharField(required=True)
    mobile_otp = serializers.CharField(required=True)

    