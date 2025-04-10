from unittest.mock import MagicMock
from flask_jwt_extended import decode_token, create_access_token
from app import app as flask_app
from db import read_firestore_doc


def test_read_firestore_doc():
    key = 'accounts/123'
    collection_name, document_id = key.split('/')
    assert collection_name == 'accounts'
    assert document_id == '123'

def test_legacy_user_login(client, mock_legacy_user):
    response = client.post('/login', json={'email': 'user1@email.com', 'password': '123'})
    assert response.status_code == 200
    r = response.get_json()
    assert 'access_token' in r
    assert 'refresh_token' in r
    claims = decode_token(r.get('access_token'))
    assert claims.get('sub') == "account1"
    assert claims.get('email') == None # legacy_user does not have email
    assert claims.get('role') == None # legacy_user role is None

def test_sub_user_login(client, mock_sub_user):
    response = client.post('/login', json={'email': 'subuser1@email.com', 'password': '123'})
    assert response.status_code == 200
    r = response.get_json()
    assert 'access_token' in r
    assert 'refresh_token' in r
    claims = decode_token(r.get('access_token'))
    assert claims.get('sub') == "account1"
    assert claims.get('email') == 'subuser1@email.com' # sub user should have email
    assert claims.get('role') == None # legacy_user role is None

def test_get_legacy_user_info_success(client, mock_legacy_user):
    with flask_app.test_request_context():
        token = create_access_token(identity="account1")

    response = client.get('/get_account_info', headers={
        'X-API-KEY': '123',
        'Authorization': f'Bearer {token}'
    })
    assert response.status_code == 200
    r = response.get_json()
    assert r.get('email') == 'user1@email.com' # account email

def test_get_sub_user_info_success(client, mock_sub_user):
    with flask_app.test_request_context():
        token = create_access_token(identity="account1", additional_claims={'email': "subuser1@email.com"})

    response = client.get('/get_account_info', headers={
        'X-API-KEY': '123',
        'Authorization': f'Bearer {token}'
    })
    assert response.status_code == 200
    r = response.get_json()
    assert r.get('email') == 'subuser1@email.com' # sub user email


def test_update_legacy_user_info_without_email_success(client, mock_legacy_user):
    with flask_app.test_request_context():
        token = create_access_token(identity="account1")

    response = client.put('/update_account_info', headers={
        'X-API-KEY': '123',
        'Authorization': f'Bearer {token}'
    }, json={'first_name': '123', 'last_name': '123', 'phone': '123'})
    assert response.status_code == 200
    assert response.get_json().get('message') == 'Account details updated successfully'
    user_data = read_firestore_doc(f'users/user1@email.com')
    assert user_data.get('first_name') == '123'
    assert user_data.get('last_name') == '123'
    assert user_data.get('phone') == '123'

def test_update_legacy_user_info_with_email_success(client, mock_legacy_user, mocker):
    def mock_send_email(to_email, subject, body):
        mock = MagicMock()
        mock.to_email = to_email
        mock.subject = subject
        mock.body = body
        return mock

    with flask_app.test_request_context():
        token = create_access_token(identity="account1")

    mocked_send = mocker.patch('app.send_confirmation_email', return_value=mock_send_email)
    response = client.put('/update_account_info', headers={
        'X-API-KEY': '123',
        'Authorization': f'Bearer {token}'
    }, json={'email': 'user1updated@email.com'})
    assert response.status_code == 200
    assert response.get_json().get('message') == 'Account details and email updated successfully'
    # Verify account
    account_data = read_firestore_doc(f'accounts/account1')
    # ensure account's email has updated
    assert account_data.get('email') == 'user1updated@email.com'
    assert account_data.get('email_not_confirmed') == True
    assert account_data.get('email_confirm_token')
    # Verify legacy user
    user_data = read_firestore_doc(f'users/user1@email.com')
    assert user_data == None
    user_data = read_firestore_doc(f'users/user1updated@email.com')
    # ensure account's email has updated
    assert user_data.get('account_id') == 'account1'
    # legacy user's email is always null
    assert user_data.get('email') == None

    # Ensure email called
    mocked_send.assert_called_once()

def test_update_sub_user_info_with_email(client, mock_sub_user):
    with flask_app.test_request_context():
        token = create_access_token(
            identity="account1",
            additional_claims={'email': 'subuser1@email.com'}
        )

    response = client.put('/update_account_info', headers={
        'X-API-KEY': '123',
        'Authorization': f'Bearer {token}'
    }, json={'email': 'subuser1updated@email.com'})
    assert response.status_code == 403
    assert response.get_json().get('error') == 'You do not have permission to change the email address associated with this account'

def test_confirm_account_email_success(client, mock_legacy_user, mock_token):
    _, token = mock_token
    response = client.get('/confirm_account_email', query_string={'token': token})
    assert response.status_code == 200
    assert response.get_json().get('message') == 'Account email verified successfully'
    account_data = read_firestore_doc(f'accounts/account1')
    assert account_data.get('email_not_confirmed') == False
    assert account_data.get('email_confirm_token') == None