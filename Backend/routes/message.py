from fastapi import APIRouter, Cookie, HTTPException, UploadFile, File, Form, BackgroundTasks
import time, hashlib, base64, json, tempfile, shutil, os, secrets, io
from pydantic import BaseModel
from config import pepper, MESSAGE_LIMIT, FILE_DIMENSION_LIMIT, PUBLIC_KEY_COOLDOWN, MAX_MESSAGE_LIMIT, UPLOAD_DIR, UPLOAD_FAST
from cryptography_ import encrypt_with_age, key_gen_age, encrypt_vault, derive_signing_keys_from_age_private, calculate_message_sign, key_sign_gen, get_file_sha256, encrypt_file_with_age
from databaseInteractions import get_chat_chyper_keys, get_group_chyper_keys, set_user_vault
from utils import  is_logged_in, get_current_local_age_key, ensure_chat_seq
from telethon.tl.types import DocumentAttributeFilename
import FastTelethonhelper
from realtime import broadcast_event 

router = APIRouter()

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

async def send_public_if_not_exist(chat_id, login_session, chat_id_hash, data):
    chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
    current_key = get_current_local_age_key(chat_data)
    if not current_key or not current_key.get('pubblica'):
            _ = await send_public_key(iniz(chat_id=chat_id), login_session)
            chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
            current_key = get_current_local_age_key(chat_data)

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

async def process_file_upload_task(
    tmp_in_path: str, original_filename: str, mime_type: str, 
    chat_id: int, text: str, cryph: bool, group: bool, 
    temp_msg_id: str, temp_session_id: str, login_session: str, 
    data: dict, client
):
    try:
        chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()        

        if not cryph:
            size = os.path.getsize(tmp_in_path)
            if size < UPLOAD_FAST:
                sent_msg = await client.send_file(chat_id, tmp_in_path, caption=text, force_document=True, attributes=[DocumentAttributeFilename(original_filename)])
            else:
                uploaded = await getattr(FastTelethonhelper, 'fast_upload')(client, tmp_in_path)
                sent_msg = await client.send_file(chat_id, uploaded, caption=text, force_document=True, attributes=[DocumentAttributeFilename(original_filename)])

            sent_id = getattr(sent_msg, 'id', None)
        else:
            id_mess = secrets.token_hex(16)
            await send_public_if_not_exist(chat_id, login_session, chat_id_hash, data)

            keys_dict = get_group_chyper_keys(data, chat_id) if group else get_chat_chyper_keys(data, chat_id)
            kids = []
            recipient_keys = []

            for kid, key in keys_dict.items():
                if key:
                    kids.append(kid)
                    recipient_keys.append(key)

            file_hash = get_file_sha256(tmp_in_path)
            chat_entry = data['data']['chats'][chat_id_hash]
            sign_private = chat_entry['kid'].get(chat_entry['kid_corrente'])
            
            file_sign = calculate_message_sign(sign_private, file_hash=file_hash)
            seq = ensure_chat_seq(data, chat_id_hash) + 1
            data['data']['chats'][chat_id_hash]['seq'] = seq

            username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
            if 'masterkey' in data['data']:
                temp_data = data['data'].copy()
                del temp_data['masterkey']
                vault_ciphered = encrypt_vault(temp_data, data['data']['masterkey'])
            else:
                vault_ciphered = encrypt_vault(data['data'], data['data']['masterkey'])
            set_user_vault(username, vault_ciphered)
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=".age") as tmp_age:
                tmp_age_path = tmp_age.name
            
            if not encrypt_file_with_age(tmp_in_path, tmp_age_path, list(recipient_keys)):
                raise Exception("Errore cifratura age")

            sign = calculate_message_sign(sign_private, seq, chat_entry['kid_corrente'], chat_entry['kid_cif_corrente'], id_mess, "file", list(kids), text)
            
            inner_metadata = {
                "filename": original_filename, "cif": "file", "text": text, "mime": mime_type,
                "size": os.path.getsize(tmp_in_path), "id": id_mess, "kid": chat_entry['kid_corrente'],
                "kid_cif": chat_entry['kid_cif_corrente'], "seq": seq, "sign": sign, "kids": list(kids), "file_sign": file_sign
            }
            
            cif_inner_meta = encrypt_with_age(json.dumps(inner_metadata, sort_keys=True), list(recipient_keys))
            
            outer_metadata = {
                "cif": "file", "text": cif_inner_meta, "id": id_mess, "kid": chat_entry['kid_corrente'],
                "kid_cif": chat_entry['kid_cif_corrente'], "seq": seq, "sign": sign, "kids": list(kids)
            }
            
            meta_bytes = json.dumps(outer_metadata, sort_keys=True).encode('utf-8')
            with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as tmp_final:
                tmp_final_path = tmp_final.name
                tmp_final.write(len(meta_bytes).to_bytes(4, byteorder='big'))
                tmp_final.write(meta_bytes)
                with open(tmp_age_path, 'rb') as f_age:
                    shutil.copyfileobj(f_age, tmp_final)

            try:
                final_size = os.path.getsize(tmp_final_path)

                if final_size < UPLOAD_FAST:
                    sent_msg = await client.send_file(chat_id, tmp_final_path, caption=json.dumps({"cif":"file"}), force_document=True, attributes=[DocumentAttributeFilename(f"{secrets.token_hex(8)}.dat")])
                else:
                    uploaded = await getattr(FastTelethonhelper, 'fast_upload')(client, tmp_final_path)
                    sent_msg = await client.send_file(chat_id, uploaded, caption=json.dumps({"cif":"file"}), force_document=True, attributes=[DocumentAttributeFilename(f"{secrets.token_hex(8)}.dat")])

                sent_id = getattr(sent_msg, 'id', None)
            finally:
                for p in [tmp_age_path, tmp_final_path]:
                    if os.path.exists(p): os.remove(p)

        await broadcast_event(temp_session_id, chat_id, {"event_type": "upload_success", "chat_id": chat_id, "temp_msg_id": temp_msg_id, "message_id": sent_id})
    except Exception as e:
        await broadcast_event(temp_session_id, chat_id, {"event_type": "upload_error", "chat_id": chat_id, "temp_msg_id": temp_msg_id, "error": str(e)})
    finally:
        if os.path.exists(tmp_in_path): os.remove(tmp_in_path)

@router.post("/messages/send/file")
async def s_file(
    background_tasks: BackgroundTasks,
    chat_id: int = Form(...), 
    text: str = Form(""), 
    cryph: bool = Form(False), 
    group: bool = Form(False), 
    temp_msg_id: str = Form(""),
    file: UploadFile = File(...), 
    login_session: str = Cookie(None)
):
    temp_session_id, data = is_logged_in(login_session, True)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    if len(text) > MAX_MESSAGE_LIMIT:
        raise HTTPException(status_code=413, detail="caption troppo lunga")
 
    file_extension = os.path.splitext(file.filename)[1]
    local_filename = f"upload_{secrets.token_hex(8)}{file_extension}"
    tmp_path = os.path.join(UPLOAD_DIR, local_filename)

    try:
        with open(tmp_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024) 
                if not chunk:
                    break
                buffer.write(chunk)
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise HTTPException(status_code=500)

    try:
        size = os.path.getsize(tmp_path)
    except Exception:
        size = 0

    if size > FILE_DIMENSION_LIMIT:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise HTTPException(status_code=413, detail="File troppo grande per essere processato")

    background_tasks.add_task(
        process_file_upload_task,
        tmp_path,
        file.filename, 
        file.content_type, 
        chat_id, text, cryph, group, 
        temp_msg_id, temp_session_id, login_session, 
        data, client
    )

    return {"status": "processing", "temp_msg_id": temp_msg_id}
        
@router.post("/messages/send")
async def s_message( message: message, login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    if not client.is_connected():
        await client.connect()

    if not message.cryph:
        
        try:
            if len(message.text) > MESSAGE_LIMIT:
                splitted_text = [message.text[i:i + MESSAGE_LIMIT] for i in range(0, len(message.text), MESSAGE_LIMIT)]
                for text in splitted_text:
                    await client.send_message(message.chat_id, text)
                return {"status": "ok"}
            else:
                sent_msg = await client.send_message(message.chat_id, message.text)
                return {"status": "ok", "message_id": sent_msg.id}

        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        
    else:
        id_messagge = secrets.token_hex(16)
        chat_id_hash = hashlib.sha256(pepper.encode() + str(message.chat_id).encode()).hexdigest()        

        await send_public_if_not_exist(message.chat_id, login_session, chat_id_hash, data)
        
        if message.group:
            
            keys = get_group_chyper_keys(data, message.chat_id)

            
        else:
            
            keys = get_chat_chyper_keys(data, message.chat_id)
        
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
        
        seq = ensure_chat_seq(data, chat_id_hash) + 1
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

        sign = calculate_message_sign(sign_private, seq, kid, kid_cif, id_messagge, "on", kids, message.text)

        da_cifrare ={
            "cif" : "on",
            "text" : message.text,
            "id": id_messagge,
            "kid": kid,
            "kid_cif": kid_cif,
            "seq": seq,
            "sign": sign,
            "kids": kids
        }

        json_da_cifrare = json.dumps(da_cifrare, sort_keys= True)
        text_cyp = encrypt_with_age(json_da_cifrare, recipient_keys)
        
        if text_cyp is None:
            raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")
        
        short_payload = {
            "cif" : "on",
            "text" : text_cyp,
            "id" : id_messagge,
            "kid": kid,
            "kids": kids,
            "kid_cif": kid_cif,
            "seq": seq,
            "sign": sign
        }

        json_shot_payload = json.dumps(short_payload)
        
        if len(json_shot_payload) > MESSAGE_LIMIT:
            sign = calculate_message_sign(sign_private, seq, kid, kid_cif, id_messagge, "message", kids, message.text)
            token = secrets.token_hex(8)
            nome_file = token + ".dat"
            message_bytes = message.text.encode("utf-8")
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

            if encrypted_metadata is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")
            
            payload = metadata_size.to_bytes(4, byteorder="big") + metadata_bytes + encrypted_metadata.encode('utf-8')
            

            #in questo modo posso inviare trattare il payload come file, senza però salvarlo sul disco
            file_in_ram = io.BytesIO(payload)
            file_in_ram.name = nome_file

            caption = {
                "cif":"message",
            }

            try:
                file_in_ram.seek(0)
                sent_msg = await client.send_file(
                    message.chat_id,
                    file_in_ram,
                    caption=json.dumps(caption),
                    force_document=True,
                    attributes=[DocumentAttributeFilename(nome_file)]
                )
                return {"status": "ok", "message_id": getattr(sent_msg, 'id', None)}
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
            
        try:
            sent_msg = await client.send_message(message.chat_id, json_shot_payload)
            return {"status": "ok", "message_id": getattr(sent_msg, 'id', None)}
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")

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
    current_key = get_current_local_age_key(chat_data)
    
    
    if not current_key:
        private_sign, public_sign, kid = key_sign_gen()
        if chat_id_hash not in data['data']['chats'] or not isinstance(data['data']['chats'][chat_id_hash], dict):
            data['data']['chats'][chat_id_hash] = {}
        data['data']['chats'][chat_id_hash]['chiave_identita'] = {'privata': private_sign, 'publica': public_sign, 'kid': kid}

    elif current_key.get('inizio'):
        inizio_corrente = current_key.get('inizio', 0)
        if time.time() - inizio_corrente < PUBLIC_KEY_COOLDOWN:
            raise HTTPException(status_code=409, detail="Aspetta più tempo per generare un'altra chiave per questa chat")

    public, private = key_gen_age()

    if public is None or private is None:
        raise HTTPException(status_code=500)

    derivated = derive_signing_keys_from_age_private(private)
    second_kid = base64.urlsafe_b64encode(hashlib.sha256(private.encode("ascii")).digest()[:16]).decode()

    existing_age_kid_map = chat_data.get('chiavi_cif', {})
    if not isinstance(existing_age_kid_map, dict):
        existing_age_kid_map = {}
    updated_age_kid_map = dict(existing_age_kid_map)
    updated_age_kid_map[second_kid] = {
        'privata': private,
        'pubblica': public,
        'inizio': time.time(),
    }
    
    updated_kid_map = dict(chat_data.get('kid', {}) if isinstance(chat_data.get('kid', {}), dict) else {})
    updated_kid_map[derivated['kid']] = derivated['private_key']

    seq_value = chat_data.get('seq') if isinstance(chat_data.get('seq'), int) else 0
         
    data['data']['chats'][chat_id_hash]['chiavi_cif'] = updated_age_kid_map
    data['data']['chats'][chat_id_hash]['seq'] = seq_value
    data['data']['chats'][chat_id_hash]['kid'] = updated_kid_map
    data['data']['chats'][chat_id_hash]['kid_corrente'] = derivated['kid']
    data['data']['chats'][chat_id_hash]['kid_cif_corrente'] = second_kid
    
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    if 'masterkey' in data['data']:
        temp_data = data['data'].copy()
        del temp_data['masterkey']
        ciphered_vault = encrypt_vault(temp_data, data['data']['masterkey'])
        
    else:
        ciphered_vault = encrypt_vault(data['data'], data['data']['masterkey'])

    set_user_vault(username, ciphered_vault)
    
    if not current_key:
        message_payload = {
            "cif":"in",
            "public":public,
            'kid': derivated['kid'],
            'kid_cif': second_kid,
            'pub_sign': derivated['public_key'],
            'ikey':public_sign
        }
        
    else:
        message_payload = {
            "cif":"in",
            "public":public,
            'kid': derivated['kid'],
            'kid_cif': second_kid,
            'pub_sign': derivated['public_key'],
            'sign': calculate_message_sign(data['data']['chats'][chat_id_hash]['chiave_identita'].get('privata') , public, derivated['kid'], second_kid, derivated['public_key'], identity= True)
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
