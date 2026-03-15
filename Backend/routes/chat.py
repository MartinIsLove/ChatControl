from fastapi import APIRouter, Cookie, WebSocket, WebSocketDisconnect, HTTPException
import sqlite3, hashlib, json, base64, subprocess, tempfile, io, os, mimetypes
from database.sqlite import get_connection, db_lock
from config import pepper
from databaseInteractions import store_public_key_in_vault, get_gruppo_vault, get_chat_vault, chats_vault_update
from cryptography_ import decrypt_file_with_age, verify_message_sign, calculate_message_sign, encrypt_vault
from utils import is_logged_in, is_valid_age_public_key, is_group_chat_id, build_candidate_privates, set_media
from realtime import connect_socket, disconnect_socket, register_telethon_handlers, index_messages
from telethon.tl.types import MessageService, MessageActionChatCreate, MessageActionChatDeleteUser, MessageActionChatAddUser, MessageActionPinMessage
from datetime import datetime
from fastapi.responses import StreamingResponse


router = APIRouter()

#questa funzione inizializza la WebSocket per l'aggiornamento in tempo reali dei messaggi
@router.websocket("/ws/chats/{chat_id}")
async def chat_events(websocket: WebSocket, chat_id: int):
    login_session = websocket.cookies.get("login_session")
    try:
        temp_id, data = is_logged_in(login_session, False)
    except HTTPException:
        await websocket.close(code=1008)
        return

    client = data["client"]
    if not client.is_connected():
        await client.connect()

    register_telethon_handlers(client, temp_id, login_session)
    await connect_socket(temp_id, chat_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        data['active_chat_id'] = None
        await disconnect_socket(temp_id, chat_id, websocket)

@router.get("/chats")
async def get_chats(login_session: str = Cookie(None), offset_date: str = None):
    
    _, data = is_logged_in(login_session, False)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    dt = datetime.fromisoformat(offset_date) if offset_date else None

    chats = []

    async for dialog in client.iter_dialogs(limit=20, offset_date=dt):
        chat_info = {
            'id': dialog.id,
            'name': dialog.name if dialog.name else "Account Eliminato",
            'unread_count': dialog.unread_count,
            'is_user': dialog.is_user,
            'is_group': dialog.is_group,
            'is_channel': dialog.is_channel,
        }
        
        if dialog.message:
            chat_info['last_message'] = {
                'text': dialog.message.text or '',
                'date': dialog.date if dialog.message else None,
                'sender_id': dialog.message.sender_id
            }
        
        chats.append(chat_info)
        
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    #la parte di codice sottostante serve per capire se la chat contiene gia' delle chiavi pubbliche 
    # inizializzate dal nostro dispositivo, oppure no
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute(
                """SELECT contatto_id FROM contatti WHERE proprietario = ?
                
                    UNION
                    
                    SELECT gruppo_id FROM contatti_gruppo WHERE proprietario = ?""",
                (username,username)
            )
            risultati = cursor.fetchall()
            
            encrypted_ids = {row[0] for row in risultati}

            chats_data = data.get('data', {}).get('chats', {})

            for chat in chats:
                chat_id_hash = hashlib.sha256(pepper.encode() + str(chat['id']).encode()).hexdigest()
                has_remote_key = chat_id_hash in encrypted_ids
                chat_data = chats_data.get(chat_id_hash, {})
                has_own_key = False
                local_map = chat_data.get('chiavi_cif', {})
                if isinstance(local_map, dict):
                    has_own_key = any(
                        isinstance(value, dict) and bool(value.get('pubblica'))
                        for value in local_map.values()
                    )
                chat['cyphered'] = has_remote_key or has_own_key
                
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    


    return {"chats": chats}

@router.get("/chats/{chat_id}/limit/{limit}/start/{start}")
async def get_chat_messages(chat_id: int, limit: int, start: int, login_session: str = Cookie(None)):
    temp_id, data = is_logged_in(login_session, False)
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    client = data['client']
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    try:
        if is_group_chat_id(chat_id):
            insert_new_vault, chat_vault = get_gruppo_vault(username, chat_id, entity, data)
        else:
            insert_new_vault, chat_vault = await get_chat_vault(username, chat_id, client, data)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    if is_group_chat_id(chat_id):
        vault = chat_vault.setdefault('partecipanti', {})
        for participant_id, participant_data in list(vault.items()):
            if not isinstance(participant_data, dict):
                participant_data = {}
                vault[participant_id] = participant_data
            if not isinstance(participant_data.get('seq'), int):
                participant_data['seq'] = None
    else:
        vault = chat_vault
        if 'seq' not in vault or not isinstance(vault.get('seq'), int):
            vault['seq'] = None

    me = await client.get_me()
    my_id = me.id if me else None
    seq_dirty = False
    
    def verify_signed_payload(sender_id, payload_id, payload_kid, payload_kid_cif, payload_seq, payload_cif, payload_sign):
        if not isinstance(payload_id, str) or not payload_id.strip():
            return False, "questo messaggio e' stato modificato"
        if not isinstance(payload_kid, str) or not payload_kid.strip():
            return False, "chiave di firma mittente non disponibile"
        if not isinstance(payload_kid_cif, str) or not payload_kid_cif.strip():
            return False, "chiave di cifratura mittente non disponibile"
        if not isinstance(payload_cif, str) or not payload_cif.strip():
            return False, "questo messaggio e' stato modificato"
        if not isinstance(payload_sign, str) or not payload_sign.strip():
            return False, "questo messaggio e' stato modificato"

        if my_id and sender_id == my_id:
            local_kid_map = data.get('data', {}).get('chats', {}).get(chat_id_cif, {}).get('kid', {})
            sign_private = local_kid_map.get(payload_kid) if isinstance(local_kid_map, dict) else None
            if not sign_private:
                return False, "chiave di firma locale non disponibile"
            try:
                expected_sign = calculate_message_sign(sign_private, payload_seq, payload_kid, payload_kid_cif, payload_id, payload_cif)
            except ValueError:
                return False, "questo messaggio e' stato modificato"
            return (payload_sign == expected_sign), "questo messaggio e' stato modificato"

        user_str = str(sender_id)
        if is_group_chat_id(chat_id):
            _, vault = get_gruppo_vault(username, chat_id, entity, data)
            participant_data = vault.get('partecipanti').get(user_str)
            if participant_data is None and isinstance(vault, dict):
                participant_data = chat_vault.get(sender_id)
            signing_keys = participant_data.get('chiavi_firma') 
        else:
            signing_keys = chat_vault.get('chiavi_firma', {}) 

        if payload_kid not in signing_keys:
            return False, "chiave di firma mittente non disponibile"

        pub_sign = signing_keys.get(payload_kid)
        try:
            return verify_message_sign(pub_sign, payload_seq, payload_kid, payload_kid_cif, payload_id, payload_cif, payload_sign), "questo messaggio e' stato modificato"
        except ValueError:
            return False, "questo messaggio e' stato modificato"

    def mark_replay_in_history(messages_list):
        stream_last_seq = {}

        for item in reversed(messages_list):
            seq_value = item.get('_secure_seq')
            sender_key = item.get('_secure_sender_key')
            if not isinstance(seq_value, int) or sender_key is None:
                continue

            previous_seq = stream_last_seq.get(sender_key)
            if previous_seq is not None and seq_value <= previous_seq:
                item['error'] = "questo messaggio e' un reply attack"
                item.pop('secure', None)
                item.pop('chiave', None)
            else:
                stream_last_seq[sender_key] = seq_value

    async def has_duplicate_seq_in_history(sender_id, seq_value, current_msg_id):
        if sender_id is None or not isinstance(seq_value, int):
            return False

        async for history_msg in client.iter_messages(entity, from_user=sender_id, limit=100, max_id=current_msg_id-1):
            if history_msg.id == current_msg_id:
                continue

            raw_text = history_msg.message or ''
            if not raw_text:
                continue

            try:
                parsed_history = json.loads(raw_text)
            except Exception:
                continue

            if not isinstance(parsed_history, dict):
                continue

            cif_flag = parsed_history.get('CIF') or parsed_history.get('cif')
            if cif_flag not in ("on", "file", "message"):
                continue

            history_seq = parsed_history.get('seq')
            if isinstance(history_seq, int) and history_seq == seq_value:
                return True

        return False

    async def mark_replay_on_chunk_boundary(messages_list):
        oldest_by_sender = {}

        for item in reversed(messages_list):
            sender_key = item.get('_secure_sender_key')
            seq_value = item.get('_secure_seq')
            message_id = item.get('id')
            sender_id = item.get('sender_id')

            if sender_key is None or not isinstance(seq_value, int) or message_id is None:
                continue
            if sender_key in oldest_by_sender:
                continue
            if item.get('error'):
                continue

            oldest_by_sender[sender_key] = {
                'sender_id': sender_id,
                'seq': seq_value,
                'message_id': message_id,
                'message_ref': item,
            }

        if not oldest_by_sender:
            return

        candidates = list(oldest_by_sender.values())

        for candidate in candidates:
            try:
                result = await has_duplicate_seq_in_history(
                    candidate['sender_id'],
                    candidate['seq'],
                    candidate['message_id']
                )
            except Exception:
                continue

            if result is True:
                message_ref = candidate['message_ref']
                message_ref['error'] = "questo messaggio e' un reply attack"
                message_ref.pop('secure', None)
                message_ref.pop('chiave', None)

    def update_max_seq_in_vault(sender_id, seq_value):
        nonlocal seq_dirty
        if not isinstance(seq_value, int):
            return

        if is_group_chat_id(chat_id):
            sender_key = str(sender_id)
            participant_data = vault.get(sender_key)
            if participant_data is None:
                participant_data = vault.get(sender_id)
            if not isinstance(participant_data, dict):
                participant_data = {'seq': None}
                vault[sender_key] = participant_data

            current_seq = participant_data.get('seq')
            if current_seq is None or seq_value > current_seq:
                participant_data['seq'] = seq_value
                seq_dirty = True
        else:
            current_seq = vault.get('seq') if isinstance(vault.get('seq'), int) else None
            if current_seq is None or seq_value > current_seq:
                vault['seq'] = seq_value
                seq_dirty = True

    messages = []
    add_offset = start if start and start > 0 else 0
    iter_kwargs = {"limit": limit}
    if add_offset:
        iter_kwargs["add_offset"] = add_offset
    async for msg in client.iter_messages(entity, **iter_kwargs):
        sender = await msg.get_sender()
        system_message = None
        if isinstance(msg, MessageService):
            action = msg.action
            if isinstance(action, MessageActionChatCreate):
                system_message = f"Gruppo creato: {action.title}"
            elif isinstance(action, MessageActionChatDeleteUser):
                left_user = getattr(action, 'user_id', None)
                left_user_name = None
                if left_user:
                    try:
                        left_user_entity = await client.get_entity(left_user)
                        left_user_name = getattr(left_user_entity, 'username', None) or getattr(left_user_entity, 'first_name', None) or str(left_user)
                    except Exception:
                        left_user_name = str(left_user)
                if left_user_name:
                    system_message = f"{left_user_name} ha lasciato il gruppo"
                else:
                    system_message = "Un utente ha lasciato il gruppo"
            elif isinstance(action, MessageActionChatAddUser):
                added_users = getattr(action, 'users', None)
                if added_users and isinstance(added_users, list):
                    names = []
                    for user_id in added_users:
                        try:
                            user_entity = await client.get_entity(user_id)
                            name = getattr(user_entity, 'username', None) or getattr(user_entity, 'first_name', None) or str(user_id)
                        except Exception:
                            name = str(user_id)
                        names.append(name)
                    users_str = ", ".join(names)
                    system_message = f"{users_str} è entrato nel gruppo"
                else:
                    system_message = "Un utente è entrato nel gruppo"
            elif isinstance(action, MessageActionPinMessage):
                system_message = f"Un messaggio è stato pinnato nella chat(id: {msg.id})"

            else:
                system_message = "Notifica di sistema"

        message_data = {
            'id': msg.id,
            'chat_id': chat_id,
            'text': msg.message or '',
            'date': msg.date if msg.date else None,
            'sender_id': msg.sender_id,
            'sender_username': getattr(sender, 'username', None) if sender else None,
            'out': msg.out,
            'reply_to': msg.reply_to.reply_to_msg_id if msg.reply_to else None,
            'system_type': system_message,
        }
        
        if msg.media:
            set_media(msg, message_data)
        
        messages.append(message_data)

    await index_messages(temp_id, chat_id, [m.get("id") for m in messages if m.get("id") is not None])

    for mess in messages:
        if mess['system_type']:
            continue
        
        text = mess.get('text') or ''
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                mess['json'] = parsed
                mess['is_json'] = True
            else:
                mess['is_json'] = False
        except Exception:
            mess['is_json'] = False
        
        if mess['is_json'] == True:
            cif_flag = mess['json'].get('CIF') or mess['json'].get('cif')
            if cif_flag == "in":            
                if my_id and mess.get('sender_id') == my_id:
                    mess['is_json'] = False
                    mess['text'] = None
                    mess['chiave'] = "Questo messaggio e' uno scambio di chiave"
                    mess['is_system'] = True
                    continue
                public = mess['json'].get('public')
                kid = mess['json'].get('kid')
                kid_cif = mess['json'].get('kid_cif')
                pub_sign = mess['json'].get('pub_sign')
                if public is None or not is_valid_age_public_key(public) or pub_sign is None:
                    
                    continue
                store_public_key_in_vault(
                    data,
                    chat_id,
                    mess.get('sender_id'),
                    public,
                    kid=kid,
                    kid_cif=kid_cif,
                    pub_sign=pub_sign,
                    msg_date=mess.get('date'),
                    is_group=is_group_chat_id(chat_id),
                    group_title=getattr(entity, 'title', 'Gruppo')
                )
                mess['text'] = None
                mess['chiave'] = "Questo messaggio e' uno scambio di chiave"
                mess['is_system'] = True
                
            if cif_flag == "on":
                text = mess['json'].get('text')
                mess_decrypted_id_caption = mess['json'].get('id')
                seq = mess['json'].get('seq')
                kid = mess['json'].get('kid')
                kid_cif = mess['json'].get('kid_cif') or mess['json'].get('kid_age')
                sign = mess['json'].get('sign')
                
                
                firma, sign_error = verify_signed_payload(
                    mess.get('sender_id'),
                    mess_decrypted_id_caption,
                    kid,
                    kid_cif,
                    seq,
                    cif_flag,
                    sign,
                )
                if not firma:
                    mess['error'] = sign_error
                    if 'json' in mess:
                        del mess['json']
                    mess['is_json'] = False
                    continue
                
                chats_data = data['data'].get('chats', {})
                chat_keys = chats_data.get(chat_id_cif, {})
                candidate_privates = build_candidate_privates(chat_keys, kid_cif=kid_cif)

                decrypted_text = None
                

                for private in candidate_privates:
                    try:
                        
                        try:
                            text_bytes = base64.b64decode(text)
                        except:
                            text_bytes = text.encode()
                        
                        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                            keyfile.write(private)
                            keyfile_path = keyfile.name
                        try:
                            result = subprocess.run(
                                ['age', '-d', '-i', keyfile_path],
                                input=text_bytes,
                                capture_output=True,
                                check=True
                            )
                            decrypted_text = result.stdout.decode()
                            break
                        finally:
                            os.unlink(keyfile_path)
                    except Exception as e:
                        
                        continue
                if decrypted_text:
                    try:
                        dic_mes = json.loads(decrypted_text)
                        
                        if dic_mes['cif'] == "on":
                            message_decrypted_id = dic_mes.get('id')
                            sign_inside = dic_mes.get('sign')
                            kid_inside = dic_mes.get('kid')
                            kid_cif_inside = dic_mes.get('kid_cif')
                           
                            if mess_decrypted_id_caption != message_decrypted_id or sign_inside != sign or kid_inside != kid or (kid_cif and kid_cif_inside != kid_cif):
                                mess['error'] = "questo messaggio e' stato modificato"
                                if 'json' in mess:
                                    del mess['json']
                                mess['is_json'] = False
                                continue
                            sender_key = str(mess.get('sender_id')) if mess.get('sender_id') is not None else "unknown"
                            mess['_secure_seq'] = seq
                            mess['_secure_sender_key'] = sender_key
                            update_max_seq_in_vault(mess.get('sender_id'), seq)

                            mess['text'] = dic_mes['text']
                            mess['secure'] = True
                            
                            if 'json' in mess:
                                del mess['json']
                            mess['is_json'] = False
                        else:
                            mess['error'] = "questo messaggio e' stato modificato"
                            if 'json' in mess:
                                del mess['json']
                            mess['is_json'] = False
                    except Exception as e:
                        raise HTTPException(status_code=500)


            if cif_flag == "file":

                mess_id = mess.get('id')
                mess_decrypted_id_caption = mess['json'].get('id')
                seq = mess['json'].get('seq')
                kid = mess['json'].get('kid')
                kid_cif = mess['json'].get('kid_cif')
                sign = mess['json'].get('sign')

                firma, sign_error = verify_signed_payload(
                    mess.get('sender_id'),
                    mess_decrypted_id_caption,
                    kid,
                    kid_cif,
                    seq,
                    cif_flag,
                    sign,
                )
                if not firma:
                    mess['error'] = sign_error
                    if 'json' in mess:
                        del mess['json']
                    mess['is_json'] = False
                    continue
                if mess_id:
                    full_message = await client.get_messages(entity, ids=mess_id)
                    if full_message and full_message.media:
                        file_bytes = io.BytesIO()
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
                        mess['file_head'] = base64.b64encode(file_head_bytes).decode()
                        mess['file_head_size'] = len(file_head_bytes)

                        header_encrypted_metadata = None
                        if len(file_head_bytes) >= 8:
                            header_encrypted_size = int.from_bytes(file_head_bytes[4:8], byteorder='big')
                            if 0 < header_encrypted_size <= len(file_head_bytes) - 8:
                                header_encrypted_metadata = file_head_bytes[8:8 + header_encrypted_size]
    

                chats_data = data['data'].get('chats', {})
                chat_keys = chats_data.get(chat_id_cif, {})
                candidate_privates = build_candidate_privates(chat_keys, kid_cif=kid_cif)

                decrypted_text = None
                if header_encrypted_metadata:
                    for private in candidate_privates:
                        try:
                            try:
                                input_bytes = base64.b64decode(header_encrypted_metadata)
                            except Exception:
                                input_bytes = header_encrypted_metadata
                            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                                keyfile.write(private)
                                keyfile_path = keyfile.name
                            try:
                                result = subprocess.run(
                                    ['age', '-d', '-i', keyfile_path],
                                    input=input_bytes,
                                    capture_output=True,
                                    check=True
                                )
                                decrypted_text = result.stdout.decode()
                                break
                            finally:
                                os.unlink(keyfile_path)
                        except Exception:
                            continue

                if decrypted_text:
                    try:
                        dic_mes = json.loads(decrypted_text)
                        if dic_mes['cif'] == "file":
                            
                            message_decrypted_id = dic_mes.get('id')
                            sign_inside = dic_mes.get('sign')
                            kid_inside = dic_mes.get('kid')
                            kid_cif_inside = dic_mes.get('kid_cif')

                            if mess_decrypted_id_caption != message_decrypted_id or sign_inside != sign or kid_inside != kid or (kid_cif and kid_cif_inside != kid_cif):
                                mess['error'] = "questo messaggio e' stato modificato"
                                if 'json' in mess:
                                    del mess['json']
                                mess['is_json'] = False
                                continue
                            
                            mess['file'] = True
                            mess['filename'] = dic_mes['filename']
                            mess['text'] = dic_mes['text']
                            mess['mime'] = dic_mes['mime']
                            mess['size'] = dic_mes['size']
                            mess['secure'] = True
                            sender_key = str(mess.get('sender_id')) if mess.get('sender_id') is not None else "unknown"
                            mess['_secure_seq'] = seq
                            mess['_secure_sender_key'] = sender_key
                            update_max_seq_in_vault(mess.get('sender_id'), seq)


                            if 'json' in mess:
                                del mess['json']
                            mess['is_json'] = False
                        else:
                            mess['error'] = "questo messaggio e' stato modificato"
                            if 'json' in mess:
                                del mess['json']
                            mess['is_json'] = False
                    except Exception as e:
                        raise HTTPException(status_code=500)

            
            if cif_flag == "message":
                try:
                    mess_id = mess.get('id')
                    mess_decrypted_id_caption = mess['json'].get('id')
                    seq = mess['json'].get('seq')
                    kid = mess['json'].get('kid')
                    kid_cif = mess['json'].get('kid_cif')
                    sign = mess['json'].get('sign')

                    firma, sign_error = verify_signed_payload(
                        mess.get('sender_id'),
                        mess_decrypted_id_caption,
                        kid,
                        kid_cif,
                        seq,
                        cif_flag,
                        sign,
                    )
                    if not firma:
                        mess['error'] = sign_error
                        if 'json' in mess:
                            del mess['json']
                        mess['is_json'] = False
                        continue
                    if not mess_id:
                        continue

                    full_message = await client.get_messages(entity, ids=mess_id)
                    if not full_message or not full_message.media or not full_message.document:
                        continue

                    file_bytes = io.BytesIO()
                    await client.download_media(full_message, file=file_bytes)
                    file_bytes.seek(0)
                    encrypted_payload = file_bytes.getvalue()

                    chats_data = data['data'].get('chats', {})
                    chat_keys = chats_data.get(chat_id_cif, {})
                    candidate_privates = build_candidate_privates(chat_keys, kid_cif=kid_cif)

                    decrypted_payload = None
                    for private in candidate_privates:
                        try:
                            try:
                                input_bytes = base64.b64decode(encrypted_payload)
                            except Exception:
                                input_bytes = encrypted_payload
                            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                                keyfile.write(private)
                                keyfile_path = keyfile.name
                            try:
                                result = subprocess.run(
                                    ['age', '-d', '-i', keyfile_path],
                                    input=input_bytes,
                                    capture_output=True,
                                    check=True
                                )
                                decrypted_payload = result.stdout
                                break
                            finally:
                                os.unlink(keyfile_path)
                        except Exception:
                            continue
                    

                    if decrypted_payload and len(decrypted_payload) >= 4:
                        metadata_size = int.from_bytes(decrypted_payload[:4], byteorder='big')
                        if 0 < metadata_size <= len(decrypted_payload) - 4:
                            inner_metadata_bytes = decrypted_payload[4:4 + metadata_size]
                            message_bytes = decrypted_payload[4 + metadata_size:]
                            try:
                                inner_metadata_str = inner_metadata_bytes.decode('utf-8')
                                inner_metadata = json.loads(inner_metadata_str)
                            except Exception:
                                inner_metadata = None

                            if inner_metadata and inner_metadata.get('cif') == 'message':
                                firma, sign_error = verify_signed_payload(
                                    mess.get('sender_id'),
                                    inner_metadata.get('id'),
                                    inner_metadata.get('kid'),
                                    inner_metadata.get('kid_cif'),
                                    inner_metadata.get('seq'),
                                    inner_metadata.get('cif'),
                                    inner_metadata.get('sign'),
                                )
                                if not firma:
                                    mess['error'] = sign_error
                                    if 'json' in mess:
                                        del mess['json']
                                    mess['is_json'] = False
                                    continue

                                message_decrypted_id = inner_metadata.get('id')
                                
                                sign_inside = inner_metadata.get('sign')
                                kid_inside = inner_metadata.get('kid')
                                kid_cif_inside = inner_metadata.get('kid_cif')

                                if mess_decrypted_id_caption != message_decrypted_id or sign_inside != sign or kid_inside != kid or (kid_cif and kid_cif_inside != kid_cif):
                                    mess['error'] = "questo messaggio e' stato modificato"
                                    if 'json' in mess:
                                        del mess['json']
                                    mess['is_json'] = False
                                    continue

                                mess['text'] = message_bytes.decode('utf-8', errors='replace')

                                if 'json' in mess:
                                    del mess['json']
                                mess['is_json'] = False
                                mess['secure'] = True
                                mess['file'] = False
                                mess.pop('media_type', None)
                                mess.pop('filename', None)
                                mess.pop('mime', None)
                                mess.pop('size', None)
                                sender_key = str(mess.get('sender_id')) if mess.get('sender_id') is not None else "unknown"
                                seq_inner = inner_metadata.get('seq')
                                if isinstance(seq_inner, int):
                                    mess['_secure_seq'] = seq_inner
                                    mess['_secure_sender_key'] = sender_key
                                    update_max_seq_in_vault(mess.get('sender_id'), seq_inner)
                except Exception:
                    raise HTTPException(status_code=500)


    await mark_replay_on_chunk_boundary(messages)
    mark_replay_in_history(messages)
    for mess in messages:
        mess.pop('_secure_seq', None)
        mess.pop('_secure_sender_key', None)

    if seq_dirty:
        try:
            if is_group_chat_id(chat_id):
                latest_insert_new_vault, latest_chat_vault = get_gruppo_vault(username, chat_id, entity, data)
                latest_participants = latest_chat_vault.setdefault('partecipanti', {})
                if not isinstance(latest_participants, dict):
                    latest_participants = {}
                    latest_chat_vault['partecipanti'] = latest_participants

                local_participants = vault if isinstance(vault, dict) else {}
                for sender_key, local_participant in local_participants.items():
                    if not isinstance(local_participant, dict):
                        continue
                    local_seq = local_participant.get('seq')
                    if not isinstance(local_seq, int):
                        continue

                    latest_participant = latest_participants.get(sender_key)
                    if not isinstance(latest_participant, dict):
                        latest_participant = {}
                        latest_participants[sender_key] = latest_participant

                    latest_seq = latest_participant.get('seq') if isinstance(latest_participant.get('seq'), int) else None
                    if latest_seq is None or local_seq > latest_seq:
                        latest_participant['seq'] = local_seq
            else:
                latest_insert_new_vault, latest_chat_vault = await get_chat_vault(username, chat_id, client, data)
                local_seq = vault.get('seq') if isinstance(vault, dict) else None
                if isinstance(local_seq, int):
                    latest_seq = latest_chat_vault.get('seq') if isinstance(latest_chat_vault.get('seq'), int) else None
                    if latest_seq is None or local_seq > latest_seq:
                        latest_chat_vault['seq'] = local_seq


            chats_vault_update(latest_chat_vault, data, username, chat_id, latest_insert_new_vault )
            
        except sqlite3.Error as error:
            raise HTTPException(status_code=500, detail=str(error))

    messages.reverse() 
    return {"chat_id": chat_id, "messages": messages}

@router.get("/chats/{chat_id}/inits")
async def get_init_messages(chat_id: int, login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)

    client = data['client']
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    me = await client.get_me()
    my_id = me.id if me else None

    is_group = is_group_chat_id(chat_id)
    found = 0
    keys_added = 0

    async for msg in client.iter_messages(entity, search='"cif": "in"', limit=None):
        if my_id and msg.sender_id == my_id:
            continue

        text = msg.message or ''
        try:
            parsed = json.loads(text)
        except Exception:
            continue

        cif_flag = parsed.get('CIF') or parsed.get('cif')
        public = parsed.get('public')
        kid = parsed.get('kid')
        kid_cif = parsed.get('kid_cif')
        pub_sign = parsed.get('pub_sign')

        if cif_flag != "in" or not public or not is_valid_age_public_key(public):
            continue

        found += 1
        changed = store_public_key_in_vault(
            data,
            chat_id,
            msg.sender_id,
            public,
            kid=kid,
            kid_cif=kid_cif,
            pub_sign=pub_sign,
            msg_date=msg.date,
            is_group=is_group,
            group_title=getattr(entity, 'title', 'Gruppo')
        )
        if changed:
            keys_added += 1

    return {
        "chat_id": chat_id,
        "init_messages_found": found,
        "keys_added": keys_added,
    }

@router.get("/media/download/{chat_id}/{message_id}")
async def download_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    
    
    _, data = is_logged_in(login_session, False)
    client = data['client']
    
    if not client.is_connected():
        await client.connect()
    
    try:
        entity = await client.get_entity(chat_id)
        message = await client.get_messages(entity, ids=message_id)
        
        if not message:
            raise HTTPException(
                status_code=404,
                detail=f"Messaggio non trovato (chat_id={chat_id}, message_id={message_id})"
            )
        if not message.media:
            raise HTTPException(
                status_code=404,
                detail=f"Messaggio senza media (chat_id={chat_id}, message_id={message_id})"
            )
        
        file_bytes = io.BytesIO()
        await client.download_media(message, file=file_bytes)
        file_bytes.seek(0)
        
        mime_type = 'application/octet-stream'
        
        if message.sticker:
            mime_type = message.sticker.mime_type or 'image/webp'
        elif message.gif:
            mime_type = message.gif.mime_type or 'video/mp4'
        elif message.photo:
            mime_type = 'image/jpeg'
        elif message.video:
            mime_type = message.video.mime_type or 'video/mp4'
        elif message.document:
            mime_type = message.document.mime_type or 'application/octet-stream'

        
        return StreamingResponse(
            iter([file_bytes.getvalue()]),
            media_type=mime_type,
            headers={
                'Cache-Control': 'public, max-age=31536000',
                'ETag': f'"{chat_id}-{message_id}"'
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore download: {str(e)}")
    
@router.get("/media/cifrato/download/{chat_id}/{message_id}")
async def download_encrypt_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    
    if not client.is_connected():
        await client.connect()
    
    try:
        entity = await client.get_entity(chat_id)
        message = await client.get_messages(entity, ids=message_id)

        if not message:
            raise HTTPException(
                status_code=404,
                detail=f"Messaggio non trovato (chat_id={chat_id}, message_id={message_id})"
            )
        if not message.media or not message.document:
            raise HTTPException(
                status_code=404,
                detail=f"Messaggio senza documento (chat_id={chat_id}, message_id={message_id})"
            )

        filename = None
        for attr in (message.document.attributes or []):
            if hasattr(attr, 'file_name'):
                filename = attr.file_name
                break

        if not filename or not filename.endswith('.dat'):
            raise HTTPException(status_code=400, detail="Documento non cifrato")

        caption_text = message.message or ""
        try:
            caption_json = json.loads(caption_text)
        except Exception:
            raise HTTPException(status_code=400, detail="Caption non valida")

        cif_flag = caption_json.get('CIF') or caption_json.get('cif')
        if cif_flag != "file":
            raise HTTPException(status_code=400, detail="Caption non cifrata")

        chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        chats_data = data['data'].get('chats', {})
        chat_keys = chats_data.get(chat_id_cif, {})
        kid_cif = caption_json.get('kid_cif')
        candidate_privates = build_candidate_privates(chat_keys, kid_cif=kid_cif)
        if not candidate_privates:
            raise HTTPException(status_code=400, detail="Nessuna chiave disponibile")

        file_bytes = io.BytesIO()
        await client.download_media(message, file=file_bytes)
        file_bytes.seek(0)

        encrypted_payload_bytes = file_bytes.getvalue()
        if len(encrypted_payload_bytes) < 8:
            raise HTTPException(status_code=400, detail="Payload non valido")

        header_metadata_size = int.from_bytes(encrypted_payload_bytes[:4], byteorder='big')
        header_encrypted_size = int.from_bytes(encrypted_payload_bytes[4:8], byteorder='big')
        if header_encrypted_size <= 0 or header_encrypted_size > len(encrypted_payload_bytes) - 8:
            raise HTTPException(status_code=400, detail="Header metadata non valido")

        header_encrypted_metadata = encrypted_payload_bytes[8:8 + header_encrypted_size]
        decrypted_metadata_bytes = decrypt_file_with_age(header_encrypted_metadata, candidate_privates)
        if not decrypted_metadata_bytes:
            raise HTTPException(status_code=400, detail="Impossibile decifrare i metadata")

        if header_metadata_size != len(decrypted_metadata_bytes):
            raise HTTPException(status_code=400, detail="Dimensione metadata non valida")

        try:
            outer_metadata_str = decrypted_metadata_bytes.decode('utf-8')
            outer_metadata = json.loads(outer_metadata_str)
        except Exception:
            raise HTTPException(status_code=400, detail="Metadata esterni non validi")

        if outer_metadata.get('cif') != 'file':
            raise HTTPException(status_code=400, detail="Metadata esterni non cifrati")

        encrypted_body = encrypted_payload_bytes[8 + header_encrypted_size:]
        decrypted_payload = decrypt_file_with_age(encrypted_body, candidate_privates)
        if not decrypted_payload:
            raise HTTPException(status_code=400, detail="Impossibile decifrare il file")

        if len(decrypted_payload) < 4:
            raise HTTPException(status_code=400, detail="Payload non valido")

        metadata_size = int.from_bytes(decrypted_payload[:4], byteorder='big')
        if metadata_size <= 0 or metadata_size > len(decrypted_payload) - 4:
            raise HTTPException(status_code=400, detail="Dimensione metadata non valida")

        inner_metadata_bytes = decrypted_payload[4:4 + metadata_size]
        file_content = decrypted_payload[4 + metadata_size:]

        try:
            inner_metadata_str = inner_metadata_bytes.decode('utf-8')
            inner_metadata = json.loads(inner_metadata_str)
        except Exception:
            raise HTTPException(status_code=400, detail="Metadata interni non validi")

        if inner_metadata != outer_metadata:
            raise HTTPException(status_code=409, detail="Metadata non corrispondenti")

        out_filename = os.path.basename(inner_metadata.get('filename') or 'file.bin')
        mime_type = inner_metadata.get('mime') or mimetypes.guess_type(out_filename)[0] or 'application/octet-stream'

        return StreamingResponse(
            iter([file_content]),
            media_type=mime_type,
            headers={
                'Content-Disposition': f'attachment; filename="{out_filename}"',
                'Cache-Control': 'no-store'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore download: {str(e)}")
