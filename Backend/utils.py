from cryptography.fernet import Fernet
from config import secret_key
from fastapi import Cookie, HTTPException
import time, re
from telethon.tl.types import DocumentAttributeAnimated
from pydantic import BaseModel

SECRET_KEY = secret_key.decode()
cipher = Fernet(SECRET_KEY)
MESSAGE_LIMIT = 4096
SESSION_TIMEOUT = 1200

login_cache = {}

class iniz (BaseModel):
    chat_id: int


def split_message(text: str, limit: int = MESSAGE_LIMIT) -> list[str]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    return [text[i:i + limit] for i in range(0, len(text), limit)]

def is_logged_in( login_session: str = Cookie(None), set_time: bool = False):
    global login_cache
    if not login_session:
        raise HTTPException(status_code=401, detail="Sessione mancante. Effettua il login.")
    try:
        temp_id = cipher.decrypt(login_session.encode()).decode()
    except Exception:
        raise HTTPException(status_code=401, detail="Sessione non valida. Riesegui il login.")

    user_data = login_cache.get(temp_id)
    if not user_data:
        raise HTTPException(status_code=401, detail="Sessione scaduta. Riesegui il login.")
    
    current_time = time.time()

    if current_time - user_data['time'] > SESSION_TIMEOUT:
        del login_cache[temp_id]
        raise HTTPException(status_code=401, detail="Sessione scaduta. Riesegui il login.")
    
    if set_time:
        user_data['time'] = current_time
    return temp_id, user_data    

def is_valid_age_public_key(key: str):
    pattern = r"^age1[0-9a-z]{58}$"
    if re.match(pattern, key):
        return True
    return False

def build_candidate_privates(chat_keys: dict, kid_cif: str | None = None):
    if not isinstance(chat_keys, dict):
        return []

    candidate_privates = []
    seen = set()

    def _append_private(value):
        if not value or value in seen:
            return
        seen.add(value)
        candidate_privates.append(value)

    age_key_map = chat_keys.get('chiavi_cif', {})

    
    selected_key = None
    selected_key = age_key_map.get(kid_cif)

    current_kid_cif = chat_keys.get('kid_cif_corrente')

    selected_key = age_key_map.get(current_kid_cif)
    
    _append_private(selected_key.get('privata'))

    for _, key_data in sorted(
        age_key_map.items(),
        key=lambda item: (item[1] or {}).get('inizio', 0),
        reverse=True,
    ):
        _append_private(key_data.get('privata'))

    return candidate_privates

#questa funzione ritorna se la conversazione è un gruppo oppure no
def is_group_chat_id(chat_id: int) -> bool:
    try:
        return int(chat_id) < 0
    except Exception:
        return False
    
#questa funzione gestisce i media per renderli comprensibili al frontend
def set_media(msg, message_data):
    message_data['file'] = True
            
    # Controlla PRIMA sticker e gif (altrimenti finiscono come documenti)
    if msg.sticker:
        document = msg.sticker
        is_animated = any(
            isinstance(attr, DocumentAttributeAnimated)
            for attr in (document.attributes or [])
        )
        mime = document.mime_type or 'image/webp'
        if is_animated or mime in ('application/x-tgsticker', 'video/webm'):
            message_data['media_type'] = 'sticker_animated'
        else:
            message_data['media_type'] = 'sticker'
        message_data['size'] = document.size
        message_data['mime'] = mime
    
    elif msg.gif:
        message_data['media_type'] = 'gif'
        message_data['size'] = msg.gif.size
        message_data['mime'] = msg.gif.mime_type or 'video/mp4'
    
    # Documenti generici
    elif msg.document:
        document = msg.document
        message_data['media_type'] = 'document'
        message_data['filename'] = None
        message_data['mime'] = document.mime_type or 'application/octet-stream'
        message_data['size'] = document.size or 0
        
        for attr in (document.attributes or []):
            if hasattr(attr, 'file_name'):
                message_data['filename'] = attr.file_name
                break
    
    # Foto
    elif msg.photo:
        message_data['media_type'] = 'photo'
        message_data['size'] = msg.photo.size if hasattr(msg.photo, 'size') else 0
    
    # Video
    elif msg.video:
        message_data['media_type'] = 'video'
        message_data['size'] = msg.video.size if hasattr(msg.video, 'size') else 0
        message_data['mime'] = msg.video.mime_type if hasattr(msg.video, 'mime_type') else 'video/mp4'