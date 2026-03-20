from cryptography.fernet import Fernet
from config import secret_key
from fastapi import Cookie, HTTPException
import time, re, base64, io, json, asyncio
from telethon.tl.types import DocumentAttributeAnimated
from pydantic import BaseModel

SECRET_KEY = secret_key.decode()
cipher = Fernet(SECRET_KEY)
MESSAGE_LIMIT = 4096
SESSION_TIMEOUT = 1200

login_cache = {}

class iniz (BaseModel):
    chat_id: int

def are_metadata_equals(inner, outer):
    tmp_inside= inner.copy()
    tmp_inside.pop('text', None)
    tmp_outside = outer.copy()
    tmp_outside.pop('text', None)
    return tmp_inside == tmp_outside

async def take_file_data(client, entity, msg, cif_flag: str):
    try:
        mess_id = msg.get('id')
        if mess_id:
            full_message = await client.get_messages(entity, ids=mess_id)
            if not full_message or not full_message.media or not full_message.document:
                return None, None
            file_bytes = io.BytesIO()

            if cif_flag == "message":
                await client.download_media(full_message, file=file_bytes)
        
            elif cif_flag == "file":
                max_bytes = 64 * 1024
                downloaded = 0
                async for chunk in client.iter_download(full_message, offset=0, limit=max_bytes):
                    if not chunk:
                        break
                    file_bytes.write(chunk)
                    downloaded += len(chunk)
                    if downloaded >= max_bytes:
                        break

            file_bytes.seek(0)

            file_head_bytes = file_bytes.getvalue()
            
            msg['file_head'] = base64.b64encode(file_head_bytes).decode()
            msg['file_head_size'] = len(file_head_bytes)
            
            metadata_plain = None           
            header_encrypted_metadata = None
            
            offset = 0
            
            if len(file_head_bytes) >= offset + 4:
                metadata_size = int.from_bytes(file_head_bytes[offset : offset + 4], byteorder='big')
                offset += 4
                
                if 0 < metadata_size <= len(file_head_bytes) - offset:
                    metadata_bytes = file_head_bytes[offset : offset + metadata_size]
                    offset += metadata_size
                    
                    try:
                        metadata_plain_str = metadata_bytes.decode('utf-8')
                        metadata_plain = json.loads(metadata_plain_str) 
                    except Exception as e:
                        raise HTTPException(status_code=500, detail= f"parsing dei dati fallito: {e}")
                    
                    if cif_flag == "message":
                        encrypted_payload = file_head_bytes[offset : ]
                        return  metadata_plain, encrypted_payload
                    
                    elif cif_flag == "file":
                        if len(file_head_bytes) >= offset + 4:
                            encrypted_metadata_size = int.from_bytes(file_head_bytes[offset : offset + 4], byteorder='big')
                            offset += 4
                            
                            if 0 < encrypted_metadata_size <= len(file_head_bytes) - offset:
                                header_encrypted_metadata = file_head_bytes[offset : offset + encrypted_metadata_size]
                                offset += encrypted_metadata_size
                                return  metadata_plain, header_encrypted_metadata
            
    except Exception as e:
        raise HTTPException(status_code=500, detail= f"estrazione metadata e dati dal file fallita: {e}")
    # In caso non siano stati trovati i dati attesi, ritorniamo sempre una tupla coerente
    return None, None
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

def build_candidate_privates(chat_keys: dict, kids, kid_cif: str | None = None):
    
    age_key_map = chat_keys.get('chiavi_cif', {})
    selected_kid = list(set(kids) & age_key_map.keys() )
    selected_key = ''
    for kid_ in selected_kid:

        selected_key = age_key_map.get(kid_).get('privata')

    return selected_key

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

def get_current_local_age_key(chat_entry: dict | None) -> dict:
    if not isinstance(chat_entry, dict):
        return {}

    age_key_map = chat_entry.get('chiavi_cif', {})
    if not isinstance(age_key_map, dict) or not age_key_map:
        return {}

    current_kid_cif = chat_entry.get('kid_cif_corrente')
    if current_kid_cif:
        selected = age_key_map.get(current_kid_cif)
        if isinstance(selected, dict):
            return selected
    return {}

def ensure_chat_seq(data: dict, chat_id_hash: str):
    chats = data.setdefault('data', {}).setdefault('chats', {})
    chat_entry = chats.get(chat_id_hash)
    if not isinstance(chat_entry, dict):
        chat_entry = {}
        chats[chat_id_hash] = chat_entry
    if not isinstance(chat_entry.get('seq'), int):
        chat_entry['seq'] = 0
    return chat_entry['seq']

async def wait_for_public_key_message(client, chat_id: int, public_key: str, timeout: float = 2.0, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            messages = await client.get_messages(chat_id, limit=10)
        except Exception:
            messages = []
        for msg in messages or []:
            text = getattr(msg, "message", None) or getattr(msg, "text", None) or ""
            if '"cif"' in text and '"in"' in text and public_key in text:
                return True
        await asyncio.sleep(interval)
    return False
