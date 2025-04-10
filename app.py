import re
import secrets
from functools import wraps
from flask import Flask, jsonify, request, g
from flask_jwt_extended import JWTManager, get_jwt_identity, create_access_token, create_refresh_token, get_jwt, verify_jwt_in_request
from pydantic import BaseModel, EmailStr
from flask_pydantic import validate
from werkzeug.security import generate_password_hash, check_password_hash

from db import create_firestore_doc, delete_firestore_doc, firestore_doc_exists, read_firestore_doc, update_firestore_doc


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


class UserLogin(BaseModel):
  email: EmailStr
  password: str

class UserUpdate(BaseModel):
  first_name: str | None = None
  last_name: str | None = None
  phone: str | None = None
  email: EmailStr | None = None

class VerifyToken(BaseModel):
    token: str

### Decorator functions
def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        account_id = getattr(g, "account_id", None)
        if not account_id:
            return jsonify({"error": "JWT account_id missing"}), 401
        
        # Fetch API key from Firestore using the account_id
        account_data = read_firestore_doc(f"accounts/{account_id}")
        if not account_data:
            return jsonify({"error": "User not found"}), 404
        
        api_key = request.headers.get("X-API-KEY")
        if not api_key or api_key != account_data.get("api_key"):
            return jsonify({"error": "Invalid API key"}), 401
        return f(*args, **kwargs)
    return decorated

def jwt_required(type="access"):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            verify_jwt_in_request()
            token = get_jwt()
            if type == "access" and token["type"] != "access":
                return jsonify({"error": "Access token required"}), 403
            elif type == "refresh" and token["type"] != "refresh":
                return jsonify({"error": "Refresh token required"}), 403
            
            account_id = get_jwt_identity()
            # Attach the email to Flask's global context (`g`)
            g.account_id = account_id
            return f(*args, **kwargs)
        return decorated
    return decorator

def route_with_api_key(rule, **kwargs):
    def decorator(f):
        # Extract security flags from kwargs
        jwt_type = kwargs.pop("jwt_required", None)
        # Always check API-Key
        needs_api_key = kwargs.pop("api_key_required", True)

        # Apply security decorators in desired order
        wrapped_f = f
        # Apply to check APIKey second
        if needs_api_key:
            wrapped_f = api_key_required(wrapped_f)
        
        # Apply to check JWT first
        if jwt_type:
            wrapped_f = jwt_required(jwt_type)(wrapped_f)

        # Register the route
        wrapped_f = app.route(rule, **kwargs)(wrapped_f)
        return wrapped_f
    return decorator

app = Flask(__name__)
# Configure JWT settings
app.config["JWT_SECRET_KEY"] = "your-super-secret-key"  # Change this in a real application!
jwt = JWTManager(app)

# Attach the decorator to the app instance
app.route_with_api_key = route_with_api_key

def send_confirmation_email(to_email, subject, body):
    # Not implement yet
    return True

def send_confirmation_email_and_save_code(new_email: str, account_id: str, email_confirm_token: str, is_existing_user: bool):
    try:
        # Assuming there is a collection of confirm token
        create_firestore_doc(f'tokens/{email_confirm_token}', {
            'email': new_email,
            'account_id': account_id,
            'is_existing_user': is_existing_user
        })
        send_confirmation_email(new_email, subject='Email confirmation token', body=email_confirm_token)
        return True
    except Exception as e:
        raise e

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email", None)
    password = data.get("password", None)
    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    user = read_firestore_doc(f'users/{email}')
    if not user:
        return jsonify({'error': 'User does not exist'}), 404

    if check_password_hash(generate_password_hash(password), user.get('hashed_password')):
        return jsonify({'error': 'Invalid password'}), 403
       
    account_id = user.get('account_id')
    # Verify account
    account = read_firestore_doc(f'accounts/{account_id}')
    if not account:
        return jsonify({'error': 'Account does not exist'}), 404

    claims={
        'email': user.get('email', None) if user else None,
        'role': user.get('role', None) if user else None,
    }
    access_token = create_access_token(
        identity=user.get('account_id'),
        additional_claims=claims
    )  
    refresh_token = create_refresh_token(
        identity=user.get('account_id'),
        additional_claims=claims
    )  
    return jsonify(access_token=access_token, refresh_token=refresh_token)


@route_with_api_key('/get_account_info', methods=['GET'], jwt_required='access')
def get_account_info():
    jwt_claims = get_jwt()
    email = jwt_claims.get('email', None)
    if not email: # Legacy user. Get the account info from the account data doc
        account_id = get_jwt_identity()
        account_data = read_firestore_doc(f'accounts/{account_id}')
        if not account_data:
            return jsonify({'error': 'User does not exist'}), 404
        return jsonify({'email':account_data.get('email', ''), 'first_name':account_data.get('first_name', ''), 'last_name':account_data.get('last_name', ''), 'phone':account_data.get('phone', '')}), 200
    else:
        user_data = read_firestore_doc(f'users/{email}')
        if not user_data:
            return jsonify({'error': 'User does not exist'}), 404
        return jsonify({'email':email, 'first_name':user_data.get('first_name', ''), 'last_name':user_data.get('last_name', ''), 'phone':user_data.get('phone', '')}), 200


@route_with_api_key('/update_account_info', methods=['PUT'], jwt_required='access')
@validate()
def update_account_info(body: UserUpdate):
    account_id = get_jwt_identity()
    jwt_claims = get_jwt()
    user_email: str | None = jwt_claims.get('email', None)

    if not body:
        return jsonify({'error': 'No data received'}), 400

    account_data = read_firestore_doc(f'accounts/{account_id}')
    if not account_data:
        return jsonify({'error': 'Account does not exist'}), 404

    account_email = account_data.get('email', '')
    if not user_email:
        user_email = account_email # legacy user - no email in JWT claims. Get the main email for the account

    # convert Pydantic model to dict - omit None value
    new_data = body.model_dump(exclude_none=True)
    # Prepare the new user details to update
    new_user_details = {}
    for account_detail in ['first_name', 'last_name', 'phone', 'email']:
        if account_detail in new_data:
            new_user_details[account_detail] = str(new_data[account_detail])
    if not new_user_details:
        return jsonify({'error': 'No new account details received, so nothing to update'}), 400

    email_changed = False
    if body.email and body.email != user_email: # User is trying to change their email address
        # No need to verify it - Pydantic will do it automatically
        # if not re.match(r"[^@]+@[^@]+\.[^@]+", body.email):
        #     return jsonify({'error': 'Invalid email format'}), 400
        
        # Permission checks
        if jwt_claims.get('email') and jwt_claims['email'] != account_email:
            # This is a sub-user, since their email address is different from the main account email.
            # For now: 1. only the main user can change the account email, and 2. no functionality for sub-users to change their own email.
            # TODO: Add functionality for sub-users to change their own email
            return jsonify({'error': 'You do not have permission to change the email address associated with this account'}), 403
        
        user_role = jwt_claims.get('role', 'admin') # if no role claim, assume legacy user and default to admin
        if user_role not in ['admin']:
            return jsonify({'error': 'Insufficient permissions to perform this action.'}), 403

        if firestore_doc_exists(f'users/{body.email}'):
            return jsonify({'error': 'This email address is already in use'}), 409

        # Create the new user doc for the new email address (just copy over the existing one, if it exists)
        existing_user_data = read_firestore_doc(f'users/{account_email}')
        if not existing_user_data:
            existing_user_data = {'account_id': account_id}
        create_firestore_doc(f'users/{body.email}', existing_user_data)

        # Mark the account as email not confirmed, and create/save/send a confirmation code
        email_confirm_token = secrets.token_urlsafe(24) #24 bytes
        send_confirmation_email_and_save_code(body.email, account_id, email_confirm_token, is_existing_user=True)
        new_account_details = new_user_details | {'email_not_confirmed':True, 'email_confirm_token':email_confirm_token}

        delete_firestore_doc(f'users/{account_email}') # Delete the old user doc, once all above is successful
        update_firestore_doc(f'accounts/{account_id}', new_account_details)
        email_changed = True
    
    if hasattr(new_user_details, 'email'):
        new_user_details.pop('email') # email update handled above, not here
    # Improvement - Make sure user exists
    if firestore_doc_exists(f'users/{user_email}'):
        update_firestore_doc(f'users/{user_email}', new_user_details)

    if email_changed:
        return jsonify({'message':'Account details and email updated successfully', 'email_changed':True}), 200
    else:
        return jsonify({'message':'Account details updated successfully'}), 200

@app.route('/confirm_account_email', methods=['GET'])
@validate()
def confirm_account_email(query: VerifyToken):
    token_data = read_firestore_doc(f'tokens/{query.token}')
    if not token_data:
        return jsonify({'error': 'Token does not exist'}), 500
    
    account_id = token_data.get('account_id')
    account_data = read_firestore_doc(f'accounts/{account_id}')
    if not account_data:
        return jsonify({'error': 'Account does not exist'}), 404
    
    if not account_data.get('email_not_confirmed'):
        return jsonify({'message': 'Account email confirmed already'}), 200

    if query.token != account_data.get('email_confirm_token'):
        return jsonify({'error': 'Invalid token'}), 500
    
    # Asumming - update account
    update_firestore_doc(f'accounts/{account_id}', {'email_not_confirmed': False, 'email_confirm_token': None})
    # Delete verify token
    delete_firestore_doc(f'tokens/{query.token}')
    return jsonify({'message':'Account email verified successfully'}), 200

if __name__ == "__main__":
    app.run(debug=True)