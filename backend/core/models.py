from __future__ import unicode_literals
from datetime import timedelta
import datetime
import json
# import datetime
# from random import choices
# from django.conf import settings
from django.forms import ValidationError
from phonenumber_field.modelfields import PhoneNumberField
from django.db import models
# from django.contrib.auth.hashers import make_password
from django.utils import timezone
# from django.db.models.signals import pre_delete
# from django.dispatch import receiver

import requests
# from django.core.mail import send_mail

import bcrypt



class s_sms_admin_user_auth(models.Model):
    admin_id = models.AutoField(primary_key=True)
    ROLE_CHOICES = [
        ('superadmin', 'Super Admin'),
        ('appadmin', 'App Admin'),
    ]
    admin_role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='superadmin')
    admin_email_id = models.EmailField(unique=True)
    admin_mobile_number = PhoneNumberField(max_length=15)
    last_login = models.DateTimeField(blank=True, null=True)
    password = models.CharField(max_length=500)
    password_changed = models.BooleanField(default=False)  # new field to track password change
    created_dt = models.DateTimeField(auto_now_add=True)
    updated_dt = models.DateTimeField(auto_now=True)
    deld_in_src_ind = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        self.password = bcrypt.hashpw(self.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        super().save(*args, **kwargs)
        
        # need to test this syntax once logout function will created 
        # datetime.datetime.now().replace(microsecond=0)



    class Meta:
        db_table = 's_sms_admin_user_auth'


        

class s_society_user_auth(models.Model):
    user_key = models.AutoField(primary_key=True)
    user_email_id = models.EmailField(unique=True)
    user_mobile_number = PhoneNumberField(
        null=False,
        blank=False,
        help_text="Enter mobile number in the format '+91 XXXXXXXXXX'."
    )
    username = models.CharField(verbose_name="Full Name", max_length=500)
    last_login = models.DateTimeField(auto_now=True)
    created_dt = models.DateTimeField(auto_now_add=True)
    updated_dt = models.DateTimeField(auto_now=True)
    deld_in_src_ind = models.CharField(
        max_length=20,
        choices=[("N", "No"), ("Y", "Yes")],
        default="N"
    )
    email_id_verified = models.BooleanField(default=False)
    mobile_no_verified = models.BooleanField(default=False)
    email_otp = models.IntegerField(null=True, blank=True)
    mobile_otp = models.IntegerField(null=True, blank=True)
    log_otp = models.IntegerField(null=True, blank=True)
    

    def to_json(self):
        return {
            'user_key': self.user_key,
            'user_email_id': self.user_email_id,
            'user_mobile_number': str(self.user_mobile_number),
            'last_login': self.last_login.isoformat()
        }

    class Meta:
        db_table = 's_society_user_auth'

    def __str__(self):
        return self.user_email_id





class s_society_master(models.Model):
    soc_key = models.AutoField(primary_key=True)
    soc_id =  models.CharField(max_length=100, blank=True, null=False, unique=True)
    full_nm = models.CharField(verbose_name="Society Full Name", max_length=500)
    short_nm = models.CharField(verbose_name="Society Alias", max_length=50, null=True)
    contact_num = models.CharField(max_length=15,null=False,blank=False)
    email_id = models.EmailField(verbose_name="Society Email ID", max_length=100,unique=True)   #+91 786436898
    soc_enroll_dt = models.DateField(verbose_name="Enrollment Date", auto_now_add=True)
    subs_type = models.CharField(verbose_name="Subscription", max_length=50, choices=(('T', 'Trial'), ('A', 'Active'), ('I', 'Inactive')),default='T')
    eff_frm_dt  = models.DateField(verbose_name="Activation From Date")
    eff_to_dt = models.DateField(verbose_name="Activation To Date", null=True, blank=True)
    tot_flat_cnt = models.IntegerField(verbose_name='Total Number of flats', null=True, blank=True)
    postal_cd = models.PositiveBigIntegerField(verbose_name="Postal Code")
    add_line_1 = models.CharField(verbose_name="Address line 1", max_length=100, null=True)
    add_line_2 = models.CharField(verbose_name="Address line 1", max_length=100, null=True)
    landmark   = models.CharField(verbose_name="land mark", max_length=100, null=True)
    city_cd = models.CharField(verbose_name="City Code", null=True, max_length=20, default="")
    soc_city_nm = models.CharField(verbose_name="City Name", blank=True, null=True, max_length=100)
    state_cd = models.CharField(verbose_name="State Code", blank=True, null=True, max_length=20, default="")
    soc_state_nm = models.CharField(verbose_name="State Name", blank=True, null=True, max_length=100)
    cntry_cd = models.CharField(verbose_name="Country Code", blank=True, null=True, max_length=20, default="")
    soc_cntry_nm = models.CharField(verbose_name="Country Name", blank=True, null=True, max_length=100)
    deld_in_src_ind = models.CharField(max_length=20, choices=[("N", "No"),("Y", "Yes"),], default="N")
    created_dt = models.DateTimeField(verbose_name="Created Date", auto_now_add=True)
    created_by = models.CharField(verbose_name="Created By", max_length=100, blank=True, null=True)
    updated_dt = models.DateTimeField(verbose_name="Updated Date", auto_now=True)
    updated_by = models.CharField(verbose_name="Updated By", max_length=100, blank=True, null=True)


    class Meta:
        db_table = "s_society_master"
       

    def __str__(self):
        return self.full_nm + ", "+ self.soc_city_nm



    def clean(self):
        if self.eff_frm_dt >= self.eff_to_dt:
            raise ValidationError({'eff_to_dt': 'Effective to date should be greater than effective from date'}, code='invalid')

    def save(self, *args, **kwargs):
        ########################################################################################
        # Setting up the Activation to date if on trial subscription
        if self.eff_to_dt is None and self.subs_type == 'trial':
            self.eff_to_dt = self.eff_frm_dt + timedelta(15)

        if not self.soc_id:
            prefix = "SOC" + self.city_cd
            count_up = s_society_master.objects.filter(city_cd=self.city_cd).count() + 1
            count_str = str(count_up).zfill(5)
            postfix = self.short_nm
            self.soc_id = prefix + count_str + postfix
        super(s_society_master, self).save(*args, **kwargs)
        #######################################################################
        LOCATIONAPI = "https://api.postalpincode.in/pincode/"
        POSTAL_CD= requests.get(LOCATIONAPI+str(self.postal_cd))
        POSTAL_CD_INFO = json.loads(POSTAL_CD.text)
        DETAILS = POSTAL_CD_INFO [0]['PostOffice'][0]

        print(DETAILS)
        DSTRCT=DETAILS.get('District')
        ST = DETAILS.get('State')
        CNTRY = DETAILS.get('Country')
        self.soc_city_nm=DSTRCT
        self.soc_state_nm=ST
        self.soc_cntry_nm=CNTRY

        ########################################################################################
        # Updating all the fields, as they are updated after the save operation
        s_society_master.objects.filter(pk=self.pk).update(soc_id=self.soc_id,contact_num=self.contact_num,soc_city_nm=self.soc_city_nm,soc_state_nm=self.soc_state_nm,soc_cntry_nm=self.soc_cntry_nm)

class s_society_association_master(models.Model):
    soc_id = models.ForeignKey(s_society_master, on_delete=models.PROTECT,
                                   related_name='+',to_field = 'soc_id',db_column='soc_id')
    member_key = models.CharField(max_length=100, blank=True, null=False)
    member_email_id = models.ForeignKey(s_society_user_auth, on_delete=models.PROTECT,related_name='+',to_field = 'user_email_id',db_column='member_email_id')
    member_nm = models.CharField(verbose_name="Member Name", max_length=100,blank=True)
    member_contact_num = models.CharField(verbose_name="Phone Number", max_length=15,blank=True)
    # is_contact_no_verified = models.BooleanField(blank=False, default=False)
    member_role	 = models.CharField(verbose_name="Member's Role", max_length=200,
                            choices=(("P", "President"), ("T", "Treasurer"), ("S", "Secretary"),
                                     ("EC", "EC members"), ("O", "Other members")))
    eff_frm_dt = models.DateField(verbose_name="Member From Date", auto_now_add=True, blank=True, null=True)
    eff_to_dt = models.DateField(verbose_name="Member To Date", blank=True, null=True, default=None)
    deld_in_src_ind = models.CharField(max_length=20, choices=[("Y", "Yes"), ("N", "No")], default="N", blank=True,
                                       null=True)
    created_dt = models.DateTimeField(verbose_name="Created Date", auto_now_add=True, blank=True, null=True)
    created_by = models.CharField(verbose_name="Created By", max_length=100, blank=True, null=True)
    updated_dt = models.DateTimeField(verbose_name="Updated Date", auto_now=True, blank=True, null=True)
    updated_by = models.CharField(verbose_name="Updated By", max_length=100, blank=True, null=True)
    # user = models.ForeignKey(s_society_user_auth, on_delete=models.CASCADE)

    def save(self, *args, **kwargs):
        if self.member_email_id:
            self.member_contact_num = self.member_email_id.user_mobile_number
            self.member_key = self.member_email_id.user_key
            self.member_nm = self.member_email_id.username
            # self.member_role =[ self.member_role.strip('[]')]

        if not self.pk:
            # This is a new object being created
            self.updated_dt = None
        else:
            # This is an existing object being updated
            self.updated_dt = timezone.now()

        super().save(*args, **kwargs)

    


        s_society_association_master.objects.filter(pk=self.pk).update(
            member_email_id=self.member_email_id,
            member_contact_num=self.member_contact_num,
            member_key=self.member_key,
        )

    class Meta:
        db_table = "s_society_association_master"




    USERNAME_FIELD = 'member_email_id'
    REQUIRED_FIELDS = []
    

    # MEMBERS_ROLE = "member_role"
    # REQUIRED_FIELDS = ""

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True










class s_society_staff_master(models.Model):
    role = (('1', "Housekeeping"), ('2', "Security"), ('3', "Electrician"),
                  ('4', "Plumber"), ('5', "Carpentor"))
    # society_id = models.ForeignKey(s_society_master, default=0, on_delete=models.CASCADE)
    staff_name = models.CharField(verbose_name = "Staff Name", max_length=100)
    staff_role = models.CharField(verbose_name="Staff Role", max_length=100, choices=role)
    staff_address = models.TextField()
    staff_contact_number = models.CharField(verbose_name="Phone Number", max_length=15)
    staff_primary_contact = models.CharField(verbose_name="Primary Contact", max_length=15)
    deld_in_src_ind = models.CharField(max_length=20, choices=[("yes", "Yes"), ("no", "No")], default = "no", blank=True, null=True)
    created_date = models.DateField(verbose_name = "Created Date", auto_now_add = True, blank=True, null=True)
    created_by = models.ForeignKey(s_society_association_master, to_field='id', related_name = "+", on_delete = models.SET_NULL, verbose_name="Created By", max_length=100, blank=True, null=True)
    updated_date = models.DateField(verbose_name = "Updated Date", auto_now = True, blank=True, null=True)
    updated_by = models.ForeignKey(s_society_association_master, to_field='id', related_name = "+", on_delete = models.SET_NULL, verbose_name="Updated By", max_length=100, blank=True, null=True)

    class Meta:
        db_table = "s_society_staff_master"


    def _str_(self):
        return self.staff_name




class s_society_flat_residential_status(models.Model):

    status_role = (('O', "Occupied"), ('V', "Vacant"))
    person_role = (('O', "Owner"), ('V', "Tenent"))
    society_id = models.ForeignKey(s_society_master, default=0, on_delete=models.CASCADE)

    flat_number = models.CharField(verbose_name = "Flat No", max_length=100)
    flat_occupancy_status= models.CharField(verbose_name="Staff Role", max_length=100, choices=status_role)
    flat_occupied_by= models.CharField(verbose_name="Staff Role", max_length=100, choices=person_role)
    eff_frm_dt = models.DateField(verbose_name="Effective From  Date", auto_now_add=True, blank=True, null=True)
    eff_to_dt = models.DateField(verbose_name="Effective To Date", blank=True, null=True, default=None)
    deld_in_src_ind = models.CharField(max_length=20, choices=[("yes", "Yes"), ("no", "No")], default = "no", blank=True, null=True)
    created_date = models.DateField(verbose_name = "Created Date", auto_now_add = True, blank=True, null=True)
    created_by = models.ForeignKey(s_society_association_master, to_field='id', related_name = "+", on_delete = models.SET_NULL, verbose_name="Created By", max_length=100, blank=True, null=True)
    updated_date = models.DateField(verbose_name = "Updated Date", auto_now = True, blank=True, null=True)
    updated_by = models.ForeignKey(s_society_association_master, to_field='id', related_name = "+", on_delete = models.SET_NULL, verbose_name="Updated By", max_length=100, blank=True, null=True)

    class Meta:
        db_table = "s_society_flat_residential_status"




class s_society_flat_master(models.Model):

    type = (('1', "1"), ('2', "2"),('3', "3"),('4', "4"),('5', "5"))
   # person_role = (('O', "Owner"), ('V', "Tenent"))
    society_id = models.ForeignKey(s_society_master, default=0, on_delete=models.CASCADE)

    flat_no = models.CharField(verbose_name = "Flat No", max_length=100)
    flat_type= models.CharField(verbose_name="Flat Type", max_length=100, choices=type)
    flat_area_in_sqft = models.CharField(verbose_name="Flat Area in SqFt", max_length=100)
    open_area_in_sqft = models.CharField(verbose_name="Open Area in SqFt", max_length=100)


    created_date = models.DateField(verbose_name = "Created Date", auto_now_add = True, blank=True, null=True)
    created_by = models.ForeignKey(s_society_association_master, to_field='id', related_name = "+", on_delete = models.SET_NULL, verbose_name="Created By", max_length=100, blank=True, null=True)
    updated_date = models.DateField(verbose_name = "Updated Date", auto_now = True, blank=True, null=True)
    updated_by = models.ForeignKey(s_society_association_master, to_field='id', related_name = "+", on_delete = models.SET_NULL, verbose_name="Updated By", max_length=100, blank=True, null=True)

    class Meta:
        db_table = "s_society_flat_master"


    def _str_(self):
        return self.staff_name
    

