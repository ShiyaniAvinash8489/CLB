# from rest_framework.test import APITestCase
# from AppAdmin.models import User


# class TestModel(APITestCase):
#     def test_creates_user(self):
#         user = User.objects.create_user("9979989911")
#         self.assertIsInstance(user, User)
#         self.assertFalse(user.is_staff)
#         self.assertEqual(user.phone, "9979989911")

#     def test_creates_superuser(self):
#         user = User.objects.create_superuser(
#             "avinash.shiyani@gmail.com", "Admin0987", "9979989911", "password123")
#         self.assertIsInstance(user, User)
#         self.assertTrue(user.is_staff)
#         self.assertEqual(user.phone, "9979989911")

#     def test_raises_error_with_message_when_no_password_is_supplied(self):
#         with self.assertRaisesMessage(ValueError, 'password should not be none'):
#             User.objects.create_superuser(
#                 username='Admin0987', email='crycetruly@gmail.com', password='', phone="9979989911")
