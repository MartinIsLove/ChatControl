from fastapi import APIRouter, Cookie, WebSocket, WebSocketDisconnect, HTTPException
import sqlite3, hashlib, json, base64, io, os, mimetypes
from database.sqlite import get_connection, db_lock
from config import pepper
from databaseInteractions import store_public_key_in_vault, get_gruppo_vault, get_chat_vault, chats_vault_update
from cryptography_ import verify_message_sign, decrypt_with_age, calculate_message_sign
from utils import is_logged_in, is_valid_age_public_key, is_group_chat_id, build_candidate_privates, set_media
from realtime import connect_socket, disconnect_socket, register_telethon_handlers, index_messages
from telethon.tl.types import MessageService, MessageActionChatCreate, MessageActionChatDeleteUser, MessageActionChatAddUser, MessageActionPinMessage
from fastapi.responses import StreamingResponse
from messages_handler import handle_in, handle_file, handle_on, handle_message

router = APIRouter()

def verify_signed_payload(sender_id, payload_id, payload_kid, payload_kid_cif, payload_seq, payload_cif, payload_sign, chat_id, data, my_id, chat_vault, kids, text=None, file=None):
        chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        if my_id and sender_id == my_id:
            local_kid_map = data.get('data', {}).get('chats', {}).get(chat_id_cif, {}).get('kid', {})
            sign_private = local_kid_map.get(payload_kid) if isinstance(local_kid_map, dict) else None
            if not sign_private:
                return False, "chiave di firma locale non disponibile"
            try:
                if file is not None:
                    expected_sign = calculate_message_sign(sign_private, file=file)
                else:
                    expected_sign = calculate_message_sign(sign_private, payload_seq, payload_kid, payload_kid_cif, payload_id, payload_cif, kids, text)
            except ValueError:
                return False, "questo messaggio e' stato modificato"
            return (payload_sign == expected_sign), "questo messaggio e' stato modificato"

        user_str = str(sender_id)
        if is_group_chat_id(chat_id):
            participant_data = chat_vault.get('partecipanti', {}).get(user_str)
            if participant_data is None and isinstance(chat_vault, dict):
                participant_data = chat_vault.get(sender_id)
            signing_keys = participant_data.get('chiavi_firma', {}) if participant_data else {}
        else:
            signing_keys = chat_vault.get('chiavi_firma', {}) 

        if payload_kid not in signing_keys:
            return False, "chiave di firma mittente non disponibile"

        pub_sign = signing_keys.get(payload_kid)
        try:
            if file is not None:
                is_valid = verify_message_sign(pub_sign, payload_sign, file=file)
            else:
                is_valid = verify_message_sign(
                    pub_sign,
                    payload_sign,
                    seq=payload_seq,
                    kid=payload_kid,
                    kid_cif=payload_kid_cif,
                    message_id=payload_id,
                    cif=payload_cif,
                    kids=kids,
                    text=text,
                )

            return is_valid, "questo messaggio/file e' stato modificato"
        except ValueError:
            return False, "questo messaggio/file e' stato modificato"

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
async def get_chats(login_session: str = Cookie(None)):
    
    _, data = is_logged_in(login_session, False)
    client = data['client']

    if not client.is_connected():
        await client.connect()


    chats = []
    async for dialog in client.iter_dialogs(limit=None):
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

    ''' la parte di codice sottostante serve per capire se la chat contiene gia' delle chiavi pubbliche 
        inizializzate dal nostro dispositivo, oppure no'''
    
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
            _, chat_vault = get_gruppo_vault(username, chat_id, entity, data)
        else:
            _, chat_vault = await get_chat_vault(username, chat_id, client, data)
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

    def history_verify_sig(sender_id, msg_id_cap, kid, kid_cif, seq, flag, sign, kids, text):
        return verify_signed_payload(sender_id, msg_id_cap, kid, kid_cif, seq, flag, sign, chat_id, data, my_id, chat_vault, kids, text)

    def history_update_seq(sender_id, seq):
        update_max_seq_in_vault(sender_id, seq)
        return True, None
    
    for msg in messages:
        if msg['system_type']:
            continue
        
        text = msg.get('text') or ''
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                msg['json'] = parsed
                msg['is_json'] = True
            else:
                msg['is_json'] = False
        except Exception:
            msg['is_json'] = False
        
        if msg['is_json'] == True:
            cif_flag = msg['json'].get('CIF') or msg['json'].get('cif')

            if cif_flag == "in":            
                await handle_in(my_id, msg, data, entity)
                continue
            if cif_flag == "on":
                handle_on(msg, data, chat_id_cif, history_verify_sig, history_update_seq)
                continue

            if cif_flag == "file":
                await handle_file(client, entity, msg, data, chat_id_cif, history_verify_sig, history_update_seq)
                continue

            if cif_flag == "message":
                await handle_message(client, entity, msg, data, chat_id_cif, history_verify_sig, history_update_seq)
                continue

    await mark_replay_on_chunk_boundary(messages)
    mark_replay_in_history(messages)
    for msg in messages:
        msg.pop('_secure_seq', None)
        msg.pop('_secure_sender_key', None)

    if seq_dirty:
        try:
            if is_group_chat_id(chat_id):
                latest_insert_new_vault, latest_chat_vault = get_gruppo_vault(username, chat_id, entity, data)
                
                latest_participants = latest_chat_vault.setdefault('partecipanti', {})
                if not isinstance(latest_participants, dict):
                    latest_participants = {}
                    latest_chat_vault['partecipanti'] = latest_participants

                for sender_key, local_participant in vault.items():
                    local_seq = local_participant.get('seq')
                    
                    if not isinstance(local_seq, int):
                        continue

                    latest_participant = latest_participants.get(sender_key)
                    if not isinstance(latest_participant, dict):
                        latest_participant = {}
                        latest_participants[sender_key] = latest_participant

                    latest_seq = latest_participant.get('seq')
                    if not isinstance(latest_seq, int):
                        latest_seq = None

                    if latest_seq is None or local_seq > latest_seq:
                        latest_participant['seq'] = local_seq
            else:
                latest_insert_new_vault, latest_chat_vault = await get_chat_vault(username, chat_id, client, data)
                
                local_seq = vault.get('seq')
                if isinstance(local_seq, int):
                    
                    latest_seq = latest_chat_vault.get('seq')
                    if not isinstance(latest_seq, int):
                        latest_seq = None
                        
                    if latest_seq is None or local_seq > latest_seq:
                        latest_chat_vault['seq'] = local_seq

            chats_vault_update(latest_chat_vault, data, username, chat_id, latest_insert_new_vault)

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
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
        username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()

        me = await client.get_me()
        my_id = me.id if me else None
        entity = await client.get_entity(chat_id)
        message = await client.get_messages(entity, ids=message_id)
        try:
            if is_group_chat_id(chat_id):
                _, chat_vault = get_gruppo_vault(username, chat_id, entity, data)
            else:
                _, chat_vault = await get_chat_vault(username, chat_id, client, data)
        except sqlite3.Error as error:
            raise HTTPException(status_code=500, detail=str(error))
        
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
        for attr in (message.document.attributes or[]):
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

        mess = {}
       
        full_message = await client.get_messages(entity, ids=message_id)
        if full_message and full_message.media:
            file_bytes = io.BytesIO()            
            await client.download_media(full_message, file=file_bytes)
            
            file_bytes.seek(0)
            file_head_bytes = file_bytes.getvalue()
            
            mess['file_head'] = base64.b64encode(file_head_bytes).decode()
            mess['file_head_size'] = len(file_head_bytes)
            
            metadata_plain = None            
            encrypted_file = None
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
                        print(f"Errore nel parsing del metadata_plain: {e}")
                    
                    encrypted_file = file_head_bytes[offset : ]

                mess['metadata_plain'] = metadata_plain
                mess['file'] = encrypted_file

        if not mess.get('metadata_plain'):
            raise HTTPException(status_code=400, detail="Metadati non trovati o malformati nel file scaricato")

        metadata_plain = mess['metadata_plain']
        mess_decrypted_id_caption = metadata_plain.get('id')
        seq = metadata_plain.get('seq')
        kid = metadata_plain.get('kid')
        kid_cif = metadata_plain.get('kid_cif')
        sign = metadata_plain.get('sign')
        kids = metadata_plain.get('kids')
        encrypted_inner_metadata = metadata_plain.get('text')

        if not encrypted_inner_metadata:
             raise HTTPException(status_code=400, detail="Metadati cifrati mancanti")

        chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        chats_data = data['data'].get('chats', {})
        chat_keys = chats_data.get(chat_id_cif, {})
        
        private = build_candidate_privates(chat_keys, kids)
        if not private:
            raise HTTPException(status_code=400, detail="Nessuna chiave disponibile")

        inner_metadata_decrypted = decrypt_with_age(encrypted_inner_metadata, private)
        if not inner_metadata_decrypted:
            raise HTTPException(status_code=400, detail="Impossibile decifrare i metadati interni")
            
        inner_metadata = json.loads(inner_metadata_decrypted)
        
        if (metadata_plain.get('id') != inner_metadata.get('id') or
            metadata_plain.get('seq') != inner_metadata.get('seq') or
            metadata_plain.get('kid') != inner_metadata.get('kid') or
            metadata_plain.get('sign') != inner_metadata.get('sign')):
            raise HTTPException(status_code=400, detail="Metadati non coerenti: Possibile manomissione")
        
        plain_text = inner_metadata.get('text')

        firma, sign_error = verify_signed_payload(
            message.sender_id,
            mess_decrypted_id_caption,
            kid,
            kid_cif,
            seq,
            cif_flag,
            sign,
            chat_id,
            data,
            my_id,
            chat_vault,
            kids,
            text=plain_text
        )
        if not firma:
            raise HTTPException(status_code=400, detail=f"Firma messaggio non valida: {sign_error}")

        decrypted_payload = decrypt_with_age(mess['file'], private, False)
        if not decrypted_payload:
            raise HTTPException(status_code=400, detail="Impossibile decifrare il file")

        file_sign = inner_metadata.get('file_sign')
        if not file_sign:
            raise HTTPException(status_code=400, detail="Firma del file mancante nei metadati")

        file_firma, file_sign_error = verify_signed_payload(
            message.sender_id,
            None, 
            kid,
            kid_cif,
            None, 
            None,
            file_sign, 
            chat_id,
            data,
            my_id,
            chat_vault,
            kids,
            file=decrypted_payload
        )
        if not file_firma:
            raise HTTPException(status_code=400, detail=f"Firma del file non valida: {file_sign_error}")

        out_filename = os.path.basename(inner_metadata.get('filename') or 'file.bin')
        mime_type = inner_metadata.get('mime') or mimetypes.guess_type(out_filename)[0] or 'application/octet-stream'

        if isinstance(decrypted_payload, (bytes, bytearray)):
            payload_iter = iter([decrypted_payload])
        else:
            payload_iter = iter(decrypted_payload)

        return StreamingResponse(
            payload_iter,
            media_type=mime_type,
            headers={
                'Content-Disposition': f'attachment; filename="{out_filename}"',
                'Cache-Control': 'no-store'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore download: {str(e)}")
