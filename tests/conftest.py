

import secrets
from unittest.mock import patch
import pytest
from mockfirestore import MockFirestore
from werkzeug.security import generate_password_hash

@pytest.fixture
def mock_firestore():
    mock_db = MockFirestore()
    return mock_db

@pytest.fixture
def client(mocker, mock_firestore):
     with patch('db.db', new=mock_firestore):
        from app import app
        with app.test_client() as client:
            yield client
            
@pytest.fixture
def mock_legacy_user(mock_firestore):
    mock_firestore.collection('accounts').document('account1').set({'account_id': 'account1', 'email': 'user1@email.com', 'api_key': '123'})
    # No email in User document
    mock_firestore.collection('users').document('user1@email.com').set({'account_id': 'account1', 'hashed_password': generate_password_hash('123')})
    return mock_firestore

@pytest.fixture
def mock_sub_user(mock_firestore):
    mock_firestore.collection('accounts').document('account1').set({'account_id': 'account1', 'email': 'account1@email.com', 'api_key': '123'})
    # Having email in User document and it s different from accounts
    mock_firestore.collection('users').document('subuser1@email.com').set({'account_id': 'account1', 'email': 'subuser1@email.com', 'hashed_password': generate_password_hash('123')})
    return mock_firestore

@pytest.fixture
def mock_token(mock_firestore):
    token = secrets.token_urlsafe(24)
    mock_firestore.collection('accounts').document('account1').set({'account_id': 'account1', 'email': 'account1@email.com', 'api_key': '123', 'email_not_confirmed': True, 'email_confirm_token': token})
    # Having email in User document and it s different from accounts
    mock_firestore.collection('users').document('subuser1@email.com').set({'account_id': 'account1', 'email': 'subuser1@email.com', 'hashed_password': generate_password_hash('123')})
    mock_firestore.collection('tokens').document(token).set({'account_id': 'account1', 'email': 'subuser1@email.com', 'is_existing_user': True})
    return mock_firestore, token