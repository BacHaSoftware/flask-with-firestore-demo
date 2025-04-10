### Install uv
```
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Run Flask application
```
make dev
```

```
line 70 - 71 : Having an issue here, if the user updates their email.
The old user has deleted at line 66:
    delete_firestore_doc(f'users/{old_account_email}')
There is no user with old email:
    new_user_details.pop('email') # email update handled above, not here
    update_firestore_doc(f'users/{user_email}', new_user_details)