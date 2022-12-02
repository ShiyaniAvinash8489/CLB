# Courier Logistics Bazar (CLB)

#### Base URL For Admin: http://127.0.0.1:8000/admin/

#### Base URL For Agent: http://127.0.0.1:8000/agent/

#### Base URL For EndUser: http://127.0.0.1:8000/enduser/

#### Swagger URL: http://127.0.0.1:8000/swagger/

#### Swagger redoc: http://127.0.0.1:8000/redoc/

## Install Requirement

To install all packages from requirement

```bash
  pip install -r requirement.txt
```

## Migrations & Migrate

To Migration

```bash
  python manage.py makemigrations
```

To Migrate from Project to Database

```bash
  python manage.py migrate
```

## Start server

```bash
  python manage.py runserver
```

# API Reference

## Admin

### 1: Store System & Device Log

**Significance:** Device or System Logs of User will be stored in Database.

```
  Method:       POST
  API:          http://localhost:8000/admin/SystemAndDeviceLog/
  Content type: application/json
```

#### Request body:

```python
{
  "user_id": 0,
  "os_type": "string",
  "os_version": "string",
  "device": "string",
  "device_type": "string",
  "browser": "string",
  "brower_version": "string"
}
```

#### Response body:

- **Success body:**

  **Code:** 201

  **Body:**

  ```python
  {
  "code": 201,
  "message": "Log has been stored.",
  "data": "Encrypt – Response Payload "
  }

  ```

### 2: Register Admin User

**Significance:** Super Admin will be able to create Normal Admin User.

```
  Authorization :   Bearer <Access Token>
  Method:           POST
  API:              http://localhost:8000/admin/RegisterAdminUser/
  Content type:     application/json
```

#### Payload:

````python
{
  'first_name': 'string',
  'last_name': 'string',
  'username': 'string',
  'country_code': 'string',
  'phone': 'string',
  'email': 'string',
  'password': 'string',
}



#### Request body:
```python
{
  "data": 'Encrypt_Payload',
  "user_tnc": Boolean,

}
````

#### Response body:

- **Success body:**

  **Code:** 201

  **Body:**

  ```python
  {
  " response_code ": 201,
  "response_message": "Admin User is Successfully registered. send Email for Verifing on your registerd Email",
  " response_data ": " Encrypt – Response Payload "

  }
  ```

### 3: Super Admin Login

**Significance:** Super Admin will login.

```
  Method:       POST
  API:          http://localhost:8000/admin/SuperAdminLogin/
  Content type: application/json
```

#### Payload:

````python
{
  'email': 'string',
  'password': 'string',
}



#### Request body:
```python
{
  "data": 'Encrypt_Payload',
}
````

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  " response_code ": 200,
  "response_message": "The Login OTP has been sent to registered phone number.  ",
  " response_data ": " Encrypt – Response Payload "

  }
  ```

### 4: Admin Login

**Significance:** Admin will login.

```
  Method:       POST
  API:          http://localhost:8000/admin/AdminLogin/
  Content type: application/json
```

#### Payload:

````python
{
  'email': 'string',
  'password': 'string',
}



#### Request body:
```python
{
  "data": 'Encrypt_Payload',
}
````

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  " response_code ": 200,
  "response_message": "The Login OTP has been sent to registered phone number.  ",
  " response_data ": " Encrypt – Response Payload "

  }
  ```

### 5: Admin Verify Login OTP

**Significance:** Verify Mobile OTP which will be received on Mobile.

```
  Method:   POST
  API:      http://localhost:8000/admin/AdminVerifyLoginOTP/
  Content type: application/json
```

#### Payload:

```python
{
  "country_code": "string",
  "phone": "string",
  "otpCode": "String"
}
```

#### Request body:

```python
{
  "data": "Encrypt - Payload",
}
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
    "code": 200,
    "message": "Login Successfully.",
    "data": "Encrypt Response"
  }

  ```

### 6: Update Admin Profile

**Significance:** Admin (Self) or Super admin can update profile of admin.

```
  Authorization :   Bearer <Access Token>
  Method:           PATCH
  API:              http://localhost:8000/admin/UpdateAdminUserProfile/<int:pk>/
  Content type:     application/json
```

#### Payload:

````python
{
  'first_name': 'string',
  'last_name': 'string',
  'username': 'string',
  'country_code': 'string',
  'phone': 'string',
  'email': 'string',
}



#### Request body:
```python
{
  "data": 'Encrypt_Payload',
}
````

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  " response_code ": 200,
  "response_message": "Admin User profile has been Updated",
  " response_data ": " Encrypt – Response Payload "

  }
  ```

### 7: Change Password

**Significance:** Admin (Self) or Super admin can update Change of admin.

```
  Authorization :   Bearer <Access Token>
  Method:           PATCH
  API:              http://localhost:8000/admin/ChangeAdminPassword/<int:pk>/
  Content type:     application/json
```

#### Payload:

````python
{
  'old_password': 'string',
  'new_password': 'string',
}



#### Request body:
```python
{
  "data": 'Encrypt_Payload',
}
````

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  " response_code ": 200,
  "response_message": "Admin User password has been Updated",
  }
  ```

### 8: Upload CSV File For Pincode

**Significance:** CSV File of Pincode will be uploaded by this API

```
  Method:       POST
  API:          http://localhost:8000/admin/Upload-Pincode-CSV/
  Content type: Multi Part Parser
```

#### Request body:

```python
{
  "file": File,
}
```

#### Response body:

- **Success body:**

  **Code:** 201

  **Body:**

  ```python
  {
  " response_code ": 201,
  "response_message": "21 Record added successfully",
  }
  ```

### 9: Request to forget password

**Significance:** Admin user can request to reset password for forgetting.

```
  Authorization :   Bearer <Access Token>
  Method:           POST
  API:              http://localhost:8000/admin/Request-Reset-Email/
  Content type:     application/json
```

#### Payload:

```python
{
  'email': 'string',
  "redirect_url": "string"

}
```

#### Request body:

```python
  {
    "data": 'Encrypt_Payload',
  }
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  " response_code ": 200,
  "response_message": " Email has been sent to register E-Mail.",


  }
  ```

### 10: Reset forget Password using link

**Significance:** Admin user can reset forget password.

```
  Authorization :   Bearer <Access Token>
  Method:           PATCH
  API:              http://localhost:8000/admin/Password-Reset-Complete/
  Content type:     application/json
```

#### Payload:

```python
{
  "password": "string",
  "token": "string",
  "uidb64": "string"
}
```

#### Request body:

```python
{
  "data": 'Encrypt_Payload',
}
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  " response_code ": 200,
  "response_message": "Your Password have been reseted",
  }
  ```

### 11: Get All Booking Slot

**Significance:** Admin user can get all booking slot.

```
  Authorization :   Bearer <Access Token>
  Method:           POST
  API:              http://localhost:8000/admin/Get-All-Booking-Slot/
  Content type:     application/json
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  "response_code": 200,
  "response_message": "Success",
  “response_data”: encrypt-String,

  }
  ```

### 12: Create Booking Slot

**Significance:** Admin user can create booking slot

```
  Authorization :   Bearer <Access Token>
  Method:       POST
  API:          http://localhost:8000/admin/Add-Booking-Slot/
  Content type: application/json
```

#### Request body:

```python
{
  "start_time": "string",
  "end_time": "string",
  "is_active": "True/False"

}
```

#### Response body:

- **Success body:**

  **Code:** 201

  **Body:**

  ```python
  {
  "response_code": 201,
  "response_message": "Booking Slot has been created.",
  "response_data": encrypt String

  }
  ```

### 13: Update Booking Slot

**Significance:** Admin user can update booking slot

```
  Authorization :   Bearer <Access Token>
  Method:       PATCH
  API:          http://localhost:8000/admin/Update-Booking-Slot/<int:pk>/
  Content type: application/json
```

#### Request body:

```python
{
  "start_time": "string",
  "end_time": "string",
  "is_active": "True/False"

}
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  "response_code": 200,
  "response_message": "Booking Slot has been Updated.",
  "response_data": encrypt String

  }
  ```

### 14: Delete Booking Slot

**Significance:** Admin user can delete booking slot

```
  Authorization :   Bearer <Access Token>
  Method:       PATCH
  API:          http://localhost:8000/admin/Hard-Delete-Booking-Slot/<int:pk>/
  Content type: application/json
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
  "response_code": 200,
  "response_message": "Successfully Deleted",
  }
  ```

## End User

### 1: Login & Signup

**Significance:** User can login this API. But Account will be created if User is not register. And OTP will be sent.

```
  Method:       POST
  API:          http://localhost:8000/enduser/EndUserLogin/
  Content type: application/json
```

#### Payload:

```python
{
  "country_code": "string",
  "phone": "string"
}
```

#### Request body:

```python
{
  "data ": "Encrypt - Payload ",
}
```

#### Response body:

- **Success body:**

  **Code:** 200/201

  **Body:**

  ```python
  {
  "code": 200,
  "message": "The OTP has been sent to registered phone number. ",
  "data": "Encrypt – Response Payload "
  }


  ```

### 2: Verify Mobile OTP

**Significance:** Verify Mobile OTP which will be received on Mobile.

```
  Method:   POST
  API:      http://localhost:8000/enduser/Verify_OTP/
  Content type: application/json
```

#### Payload:

```python
{
  "country_code": "string",
  "phone": "string",
  "otpCode": "String"
}
```

#### Request body:

```python
{
  "data": "Encrypt - Payload",
}
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
    "code": 200,
    "message": "Login Successfully.",
    "data": "Encrypt Response"
  }

  ```

### 3: Verify Mobile OTP

**Significance:** Verify Mobile OTP which will be received on Mobile.

```
  Method:   GET
  API:      http://localhost:8000/enduser/SearchPincode/<int:pincode>/
  Content type: application/json
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
    "code": 200,
    "message": "Success",
    "data": "Json"
  }

  ```

### 4: Create Sender Address

**Significance:** Create Sender address for sending shipment.

```
  Authorization :   Bearer <Access Token>
  Method:           POST
  API:              http://localhost:8000/enduser/CreateSenderAddress/
  Content type:     application/json
```

#### Payload:

```python
{
  "user_id": "string",
  "address_type": "string",
  "first_name" : "string",
  "last_name" : "string",
  "country_code": "string",
  "phone" : "string",
  "address" : "string",
  "landmarks" : "string",
  "city" : "string",
  "pincode" : "string",
  "country" : "string",
  "latitude" : "string",
  "longitude" : "string"
}
```

#### Request body:

```python
{
  "data": "Encrypt - Payload",
}
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
    "response_code": 201,
    "response_message": " Sender Address has been created..",
    " response_data ": "Encrypt – Response Payload ",
  }

  ```

### 5: Create Sender Address

**Significance:** Create Receiver address for Receiving shipment.

```
  Authorization :   Bearer <Access Token>
  Method:           POST
  API:              http://localhost:8000/enduser/CreateReceiverAddress/
  Content type:     application/json
```

#### Payload:

```python
{
  "user_id": "string",
  "address_type": "string",
  "first_name" : "string",
  "last_name" : "string",
  "country_code": "string",
  "phone" : "string",
  "address" : "string",
  "landmarks" : "string",
  "city" : "string",
  "pincode" : "string",
  "country" : "string",
  "latitude" : "string",
  "longitude" : "string"
}
```

#### Request body:

```python
{
  "data": "Encrypt - Payload",
}
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
    "response_code": 201,
    "response_message": " Receiver Address has been created..",
    " response_data ": "Encrypt – Response Payload ",
  }

  ```

### 6: Select Booking Slot

**Significance:** End User can book slot for picking up shipment.

```
  Authorization :   Bearer <Access Token>
  Method:           POST
  API:              http://localhost:8000/enduser/CreateReceiverAddress/
  Content type:     application/json
```

#### Request body:

```python
{
  "date": "yyyy-mm-dd",
}
```

#### Response body:

- **Success body:**

  **Code:** 200

  **Body:**

  ```python
  {
    "response_code": 200,
    "response_message": "Success",
    " response_data ": "Encrypt – Response Payload ",
  }

  ```
