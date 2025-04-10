
# Functions Overview
### `route_with_api_key`
A decorator function that checks the X-API-KEY and uses the flask_jwt_extended package to verify and retrieve user information from the JWT token on header

### `get_account_info`

Retrieves user information from Firestore:

- Verifies the bearer JWT token.
- If `additional_claims` does not include an email:
  - Treats the user as a **legacy user**.
  - Reads user info from the `accounts` collection.
- Otherwise:
  - Reads from the `users` collection.

### `update_account_info`

Updates user details:  
`first_name`, `last_name`, `phone`, `email`

#### Email Change Detection

- If the new email in the request differs from the current one, it's treated as an **email update request**.

#### Email Change Logic

- **Sub-user:**
  - Not permitted to change email.

- **Legacy User:**
  - Role validation:
    - Only `admin` role can change email.
    - If no role is defined, default to `admin`.
  - Validates email format.
  - Checks if the new email already exists.
  - Creates a new user document based on the old one, retaining `account_id`.
  - Generates a confirmation token.
  - Sends confirmation email to the new address.
  - Marks the user as `email_not_confirmed = False`.
  - Deletes the old legacy user document.

#### If Email Is Not Changing

- Removes the email field from the payload (if present).
- Proceeds with a normal update.



# Data Structured
There are **three types of users** in the system, stored across **two Firestore collections**: `accounts` and `users`.
## Firestore Collections
- **`accounts`**: Stores main users.
- **`users`**: Stores legacy users and sub-users.

## User Types
### 1. Main User
- Stored in the **`accounts`** collection.
- **Email is required**.

### 2. Legacy User
- Stored in the **`users`** collection.
- **No email** is associated with this type.
- Have `account_id` for referencing to Main User

### 3. Sub-user
- Also stored in the **`users`** collection.
- Must have a **unique email address** (different from the main user's).
- Have `account_id` for referencing to Main User

Here's the data structure I’m assuming
```
class Account(BaseModel):
    email: str
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    api_key: str | None = None
    email_not_confirmed: bool | None = None
    email_confirm_token: str | None = None

class User(BaseModel):
    hashed_password: str # Assuming
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    account_id: str
    role: str | None = None # None meants Legacy user


class SubUser(User):
    email: str  # Sub user must have email
```

# Implemented Login Endpoint and Email Verification Endpoint
As part of completing the assignment, here is what I have implemented:
### Decorator: route_with_api_key
Checks for a valid X-API-KEY and Bearer token in the request headers.

### Login Endpoint
Verifies the user's email and password, checks if the user exists in Firestore, and generates JWT tokens (`access_token` and `refresh_token`). These tokens are used in the `get_account_info` and `update_account_info` endpoints.

### Firestore Query Implementation
Implemented Firestore queries for performing CRUD operations on documents.

### confirm_account_email Function
Completes the account verification process. After sending a verification email, the end user receives a confirmation link. Upon clicking the link, they are redirected to the frontend, which should then call the `confirm_account_email` endpoint to complete the verification

# An error with original code
```
line 70 - 71 : Having an issue here, if the user updates their email.
The old user has deleted at line 66:
    delete_firestore_doc(f'users/{old_account_email}')
There is no user with old email:
    new_user_details.pop('email') # email update handled above, not here
    update_firestore_doc(f'users/{user_email}', new_user_details)
```

### Google document
```
https://docs.google.com/document/d/1QIvVMfhE1yZAG8yTFqGqnimn2PStFuAOO1BLEbUT9Hg/edit?tab=t.0#heading=h.1pfpupux06qs
```