from fastapi import APIRouter, Cookie, HTTPException, UploadFile, File, Form
import asyncio, time, hashlib, base64, json, tempfile, shutil, os, secrets, mimetypes, io
from pydantic import BaseModel
from config import pepper
from cryptography_ import encrypt_with_age, genera_chiavi, encrypt_vault, derive_signing_keys_from_age_private, calculate_message_sign
from databaseInteractions import get_chat_chyper_keys, get_group_chyper_keys, set_user_vault
from utils import  is_logged_in, split_message
from telethon.tl.types import DocumentAttributeFilename

router = APIRouter()

CAPTION_LIMIT = 1024
MESSAGE_LIMIT = 4096
MIN_UPLOAD_BPS = 32 * 1024
PUBLIC_KEY_COOLDOWN = 0

class message (BaseModel):
    text: str
    chat_id: int
    cryph: bool
    group: bool

class delete_m(BaseModel):
    chat_id: int
    message_id: int

class iniz (BaseModel):
    chat_id: int

async def send_public_if_not_exist(chat_id, login_session, client, chat_id_hash, data):
    chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
    current_key = _get_current_local_age_key(chat_data)
    if not current_key or not current_key.get('pubblica'):
            key_response = await send_public_key(iniz(chat_id=chat_id), login_session)
            public_key = key_response.get("public") if isinstance(key_response, dict) else None
            if public_key:
                key_visible = await wait_for_public_key_message(client, chat_id, public_key)
                if not key_visible:
                    raise HTTPException(status_code=503, detail="Chiave non visibile in chat, riprova")
            chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
            current_key = _get_current_local_age_key(chat_data)

def _ensure_chat_seq(data: dict, chat_id_hash: str):
    chats = data.setdefault('data', {}).setdefault('chats', {})
    chat_entry = chats.get(chat_id_hash)
    if not isinstance(chat_entry, dict):
        chat_entry = {}
        chats[chat_id_hash] = chat_entry
    if not isinstance(chat_entry.get('seq'), int):
        chat_entry['seq'] = 0
    return chat_entry['seq']

def _get_current_local_age_key(chat_entry: dict | None) -> dict:
    if not isinstance(chat_entry, dict):
        return {}

    age_key_map = chat_entry.get('chiavi_cif', {})
    if not isinstance(age_key_map, dict) or not age_key_map:
        return {}

    current_kid_cif = chat_entry.get('kid_cif_corrente')
    if isinstance(current_kid_cif, str):
        selected = age_key_map.get(current_kid_cif)
        if isinstance(selected, dict):
            return selected
    return {}

#verifica se la "public key" e' arrivata ai server di telegram e quindi e' valida
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
    
#questa funzione si occupa di eliminare un messaggio
@router.post("/messages/delete")
async def delete(message: delete_m, login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)
    client = data['client']

    if not client.is_connected():
        await client.connect()
    try:
        await client.delete_messages(message.chat_id, [message.message_id], revoke=True)
        fetched = await client.get_messages(message.chat_id, ids=message.message_id)
        if fetched is None or getattr(fetched, "deleted", False):
            return {"status": "ok"}
        return {"status": "not_deleted"}
    except Exception:
        raise HTTPException(status_code=502, detail="Non hai il permesso di cancellare questo messaggio")

#questa funzione invia un file, puo' inviarlo sia cifrato che non
@router.post("/messages/send/file")
async def s_file(chat_id: int = Form(...), text: str = Form(""), cryph: bool = Form(False),group: bool = Form(False), file: UploadFile = File(...),login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)
    client = data['client']


    if not client.is_connected():
        await client.connect()

    if not cryph:
        try:
            ext = os.path.splitext(file.filename)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                shutil.copyfileobj(file.file, tmp)
                tmp_path = tmp.name

            sent_msg = await client.send_file(
                chat_id,
                tmp_path,
                caption=text,
                force_document=True,
                attributes=[DocumentAttributeFilename(file.filename)]
            )
            os.remove(tmp_path)

            sent_id = None
            try:
                sent_id = getattr(sent_msg, 'id', None)
            except Exception:
                sent_id = None

            return {"status": "ok", "message_id": sent_id}
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")

    else:
        id_mess = secrets.token_hex(16)

        token = secrets.token_hex(8)
        nome_file = token + ".dat"

        chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

        
        await send_public_if_not_exist(chat_id, login_session, client, chat_id_hash, data)


        if group:
            keys = get_group_chyper_keys(data, chat_id)
        else:
            keys = get_chat_chyper_keys(data, chat_id)
        

        kids = []
        recipient_keys = []
        for kid, value in keys.items():
            if value is not None and kid is not None:
                kids.append(kid)
                recipient_keys.append(value)
        try:
            file_content = await file.read()

            tmp_mime, _ = mimetypes.guess_type(file.filename)
            mime = tmp_mime or file.content_type or "application/octet-stream"


            chat_entry = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
            kid = chat_entry.get('kid_corrente')
            kid_cif = chat_entry.get('kid_cif_corrente')
            sign_private = chat_entry.get('kid', {}).get(kid) if kid else None

            if not isinstance(kid_cif, str) or not kid_cif:
                raise HTTPException(status_code=500, detail="Chiave di cifratura corrente non disponibile")

            if not sign_private:
                raise HTTPException(status_code=500, detail="Chiave di firma corrente non disponibile")

            seq = _ensure_chat_seq(data, chat_id_hash) + 1
            data['data']['chats'][chat_id_hash]['seq'] = seq
            username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
            if 'masterkey' in data['data']:
                temp_data = data['data'].copy()
                del temp_data['masterkey']
                vault_ciphered = encrypt_vault(temp_data, data['data']['masterkey'])
            
            else:
                vault_ciphered = encrypt_vault(data['data'], data['data']['masterkey'])
                
            set_user_vault(username, vault_ciphered)

            sign = calculate_message_sign(sign_private, seq, kid, kid_cif, id_mess, "file", kids)

            metadata = {
                "filename": file.filename,
                "cif": "file",
                "text": text,
                "mime": mime,
                "size": len(file_content),
                "id": id_mess,
                "kid": kid,
                "kid_cif": kid_cif,
                "seq": seq,
                "sign": sign,
                "kids": kids,
            }

            json_metadata = json.dumps(metadata, sort_keys=True)
            metadata_bytes = json_metadata.encode('utf-8')
            metadata_size = len(metadata_bytes)

            encrypted_metadata = encrypt_with_age(metadata_bytes, recipient_keys)
            if encrypted_metadata is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")

            # cifro solo il metadata separatamente (già fatto) e cifro solo il file
            encrypted_file = encrypt_with_age(file_content, recipient_keys)
            if encrypted_file is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura del file con age")

            if isinstance(encrypted_metadata, str):
                encrypted_metadata = encrypted_metadata.encode('utf-8')
            if isinstance(encrypted_file, str):
                encrypted_file = encrypted_file.encode('utf-8')

            # payload: [len(metadata_plain:4)] [metadata_plain] [len(encrypted_metadata:4)] [encrypted_metadata] [encrypted_file]
            payload = (
                metadata_size.to_bytes(4, byteorder='big')
                + metadata_bytes
                + len(encrypted_metadata).to_bytes(4, byteorder='big')
                + encrypted_metadata
                + encrypted_file
            )

            encrypted_payload = payload

            caption = {
                "cif":"file",
            }

            # Salva il file cifrato con nome = token
            with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as tmp:
                if isinstance(encrypted_payload, str):
                    tmp.write(encrypted_payload.encode('utf-8'))
                else:
                    tmp.write(encrypted_payload)
                tmp_path = tmp.name
            
            # Invia il file tramite Telethon

            caption_str = json.dumps(caption)

            if len(caption_str) <= CAPTION_LIMIT:
                start_time = time.monotonic()

                async def progress_cb(current, total):
                    elapsed = time.monotonic() - start_time
                    if elapsed >= 1.0 and (current / max(elapsed, 0.001)) < MIN_UPLOAD_BPS:
                        raise Exception("Connessione troppo lenta")

                sent_msg = None
                try:
                    sent_msg = await client.send_file(
                        chat_id,
                        tmp_path,
                        caption=caption_str,
                        force_document=True,
                        attributes=[DocumentAttributeFilename(nome_file)],
                        progress_callback=progress_cb
                    )
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)

                sent_id = None
                try:
                    sent_id = getattr(sent_msg, 'id', None)
                except Exception:
                    sent_id = None

                return {"status": "ok", "message_id": sent_id}
            else:
                raise HTTPException(
                    status_code=413,
                    detail=f"caption troppo lunga ({len(caption_str)}>{CAPTION_LIMIT})"
                )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        
#questa funzione invia un messaggio normale o cifrato
@router.post("/messages/send")
async def s_message( credentials: message, login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    if not credentials.cryph:
        try:
            if len(credentials.text)>4096:
                splitted_text = split_message(credentials.text)
                for text in splitted_text:
                    await client.send_message(credentials.chat_id, text)
            else:
                await client.send_message(credentials.chat_id, credentials.text)

        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        
    else:
        id_messagge = secrets.token_hex(16)
        chat_id_hash = hashlib.sha256(pepper.encode() + str(credentials.chat_id).encode()).hexdigest()        

        await send_public_if_not_exist(credentials.chat_id, login_session, client, chat_id_hash, data)
        
        if credentials.group:
            
            keys = get_group_chyper_keys(data, credentials.chat_id)

            
        else:
            
            keys = get_chat_chyper_keys(data, credentials.chat_id)
        
        kids = []
        recipient_keys = []
        for kid, value in keys.items():
            if value is not None and kid is not None:
                recipient_keys.append(value)
                kids.append(kid)


        chat_entry = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
        kid = chat_entry.get('kid_corrente')
        kid_cif = chat_entry.get('kid_cif_corrente')
        sign_private = chat_entry.get('kid', {}).get(kid) if kid else None

        if not isinstance(kid_cif, str) or not kid_cif:
            raise HTTPException(status_code=500, detail="Chiave di cifratura corrente non disponibile")
        
        seq = _ensure_chat_seq(data, chat_id_hash) + 1
        data['data']['chats'][chat_id_hash]['seq'] = seq
        username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()

        if 'masterkey' in data['data']:
            temp_data = data['data'].copy()
            del temp_data['masterkey']
            vault_ciphered = encrypt_vault(temp_data, data['data']['masterkey'])
        
        else:
            vault_ciphered = encrypt_vault(data['data'], data['data']['masterkey'])

        set_user_vault(username, vault_ciphered)

        if not sign_private:
            raise HTTPException(status_code=500, detail="Chiave di firma corrente non disponibile")

        sign = calculate_message_sign(sign_private, seq, kid, kid_cif, id_messagge, "on", kids)

        da_cifrare ={
            "cif" : "on",
            "text" : credentials.text,
            "id": id_messagge,
            "kid": kid,
            "kid_cif": kid_cif,
            "seq": seq,
            "sign": sign
        }

        

        json_da_cifrare = json.dumps(da_cifrare, sort_keys= True)
        text_cyp = encrypt_with_age(json_da_cifrare, recipient_keys)
        
        finale = {
            "cif" : "on",
            "text" : text_cyp,
            "id" : id_messagge,
            "kid": kid,
            "kids": kids,
            "kid_cif": kid_cif,
            "seq": seq,
            "sign": sign
        }

        if text_cyp is None:
            raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")
        
        #questa parte controlla che il messaggio sia entro i limiti di splittamento di telegram
        #ovvero 4096 caratteri, nel caso positivo gestisce l'invio del messaggio come file,
        #per evitare splittamenti
        if len(json.dumps(finale)) > MESSAGE_LIMIT:
            sign = calculate_message_sign(sign_private, seq, kid, kid_cif, id_messagge, "message", kids)
            token = secrets.token_hex(8)
            nome_file = token + ".dat"
            message_bytes = credentials.text.encode("utf-8")
            message_metadata = {
                "cif": "message",
                "kids": kids,
                "id":id_messagge,
                "kid": kid,
                "kid_cif": kid_cif,
                "seq": seq,
                "sign": sign,
            }
            json_metadata = json.dumps(message_metadata, sort_keys=True)
            metadata_bytes = json_metadata.encode("utf-8")
            metadata_size = len(metadata_bytes)
            encrypted_metadata = encrypt_with_age(metadata_size.to_bytes(4, byteorder="big") + metadata_bytes + message_bytes, recipient_keys)

            payload = metadata_size.to_bytes(4, byteorder="big") + metadata_bytes + encrypted_metadata.encode('utf-8')
            if encrypted_metadata is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")


            file_in_ram = io.BytesIO(payload)
            file_in_ram.name = nome_file

            caption = {
                "cif":"message",
            }

            try:
                file_in_ram.seek(0)
                await client.send_file(
                    credentials.chat_id,
                    file_in_ram,
                    caption=json.dumps(caption),
                    force_document=True,
                    attributes=[DocumentAttributeFilename(nome_file)]
                )
                return {"status": "ok"}
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
            
        
        
        try:
            await client.send_message(credentials.chat_id, json.dumps(finale))
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
    return {"status":"ok"}

#questa funzione invia la chiave pubblica alla chat designata
@router.post("/messages/initializing")
async def send_public_key(credentials: iniz, login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    chat_id_hash = hashlib.sha256(pepper.encode() + str(credentials.chat_id).encode()).hexdigest()
    
    if 'chats' not in data['data']:
        data['data']['chats'] = {}
    
    chat_data = data['data']['chats'].get(chat_id_hash, {})
    current_key = _get_current_local_age_key(chat_data)
    
    if current_key and current_key.get('inizio'):
        inizio_corrente = current_key.get('inizio', 0)
        if time.time() - inizio_corrente < PUBLIC_KEY_COOLDOWN:
            raise HTTPException(status_code=409, detail="Aspetta più tempo per generare un'altra chiave per questa chat")

    public, privata = genera_chiavi()

    derivated = derive_signing_keys_from_age_private(privata)
    second_kid = base64.urlsafe_b64encode(hashlib.sha256(privata.encode("ascii")).digest()[:16]).decode().rstrip("=")

    existing_age_kid_map = chat_data.get('chiavi_cif', {})
    if not isinstance(existing_age_kid_map, dict):
        existing_age_kid_map = {}
    updated_age_kid_map = dict(existing_age_kid_map)
    updated_age_kid_map[second_kid] = {
        'privata': privata,
        'pubblica': public,
        'inizio': time.time(),
    }
    
    updated_kid_map = dict(chat_data.get('kid', {}) if isinstance(chat_data.get('kid', {}), dict) else {})
    updated_kid_map[derivated['kid']] = derivated['private_key']

    seq_value = chat_data.get('seq') if isinstance(chat_data.get('seq'), int) else 0

    data['data']['chats'][chat_id_hash] = {
        'chiavi_cif': updated_age_kid_map,
        'seq': seq_value,
        'kid': updated_kid_map,
        'kid_corrente': derivated['kid'],
        'kid_cif_corrente': second_kid,
    }
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    if 'masterkey' in data['data']:
        temp_data = data['data'].copy()
        del temp_data['masterkey']
        ciphered_vault = encrypt_vault(temp_data, data['data']['masterkey'])
        
    else:
        ciphered_vault = encrypt_vault(data['data'], data['data']['masterkey'])

    set_user_vault(username, ciphered_vault)

    message_payload = {
        "cif":"in",
        "public":public,
        'kid': derivated['kid'],
        'kid_cif': second_kid,
        'pub_sign': derivated['public_key']
    }
    
    try:
        await client.send_message(credentials.chat_id, json.dumps(message_payload))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")

    return {
        "status": "ok",
        "public": public,
        "kid_corrente": derivated['kid'],
        "kid_cif_corrente": second_kid,
    }
