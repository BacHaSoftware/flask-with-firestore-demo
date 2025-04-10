from typing import Any, Dict, Literal
from google.cloud import firestore

# init firestore
try:
    db = firestore.Client()
except Exception as e:
    raise Exception('Cannot connect Firestore')

    
def find_document_by_field(collection_name: Literal['accounts', 'users'], field_name, field_value):
    try:
        query = db.collection(collection_name).where(field_name, "==", field_value).limit(1)
        results = query.get()
        return results[0].to_dict() if results else None
    except Exception as e:
        print(f"Error querying Firestore: {e}")
        return None
    
def read_firestore_doc(key: str) -> Dict[str, Any] | None:
    collection, document_id = key.split('/')
    try:
        doc_ref = db.collection(collection).document(document_id)
        doc = doc_ref.get()
        if doc.exists:
            return doc.to_dict()
        return None
    except Exception as e:
        print(f"Error querying {collection} - document_id {document_id}: {e}")
        return None

def firestore_doc_exists(key: str) -> bool:
    try:
        collection, document_id = key.split('/')
        doc_ref = db.collection(collection).document(document_id)
        doc = doc_ref.get()
        if doc.exists:
            return True
        else:
            return False
    except Exception as e:
        print(f"Failed to get Firestore: {e}")
        raise e
    
def create_firestore_doc(key: str, data: Dict[str, Any]) -> bool:
    try:
        collection, document_id = key.split('/')
        doc_ref = db.collection(collection).document(document_id)
        doc_ref.set(data)
        return True
    except Exception as e:
        print(f"Error creating {collection}: {e}")
        return False
    
def delete_firestore_doc(key: str) -> bool:
    try:
        collection, document_id = key.split('/')
        doc_ref = db.collection(collection).document(document_id)
        doc_ref.delete()
        return True
    except Exception as e:
        print(f"Error deleting {collection}: {e}")
        return False
    
def update_firestore_doc(key: str, data: Dict[str, Any]) -> bool:
    collection, document_id = key.split('/')
    try:
        doc_ref = db.collection(collection).document(document_id)
        doc_ref.update(data)
        return True
    except Exception as e:
        print(f"Error updating {collection}: {e}")
        return False

