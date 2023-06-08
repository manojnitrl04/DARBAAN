# from django.contrib.auth.base_user import BaseUserManager
#
#
# class CustomUserManager(BaseUserManager):
#     def create_user(self, admin_email_id, password=None, **extra_fields):
#         """
#         Creates and saves a User with the given email and password.
#         """
#         if not admin_email_id:
#             raise ValueError('The Email field must be set')
#         email = self.normalize_email(admin_email_id)
#         user = self.model(admin_email_id=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user
#
#     def create_superuser(self, admin_email_id, password=None, **extra_fields):
#         """
#         Creates and saves a superuser with the given email and password.
#         """
#         extra_fields.setdefault('admin_role', 'superadmin')
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
#
#         if extra_fields.get('admin_role') != 'superadmin':
#             raise ValueError('Superuser must have admin_role="superadmin".')
#
#         return self.create_user(admin_email_id, password, **extra_fields)
