from fastapi import APIRouter, Cookie, WebSocket, WebSocketDisconnect, HTTPException
import sqlite3, hashlib, json, tempfile, io, os, asyncio, time, subprocess
from datetime import datetime
from database.sqlite import get_connection, db_lock
from config import pepper
from databaseInteractions import store_public_key_in_vault, get_gruppo_vault, get_chat_vault, chats_vault_update, set_user_vault
from cryptography_ import verify_message_sign, decrypt_with_age, calculate_message_sign, encrypt_vault
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
    
    async for msg in client.iter_messages(entity, limit = limit, add_offset = add_offset):
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
    chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    last_modify = data.get('data', {}).get('chats', {}).get(chat_id_hash, {}).get('time', None)
    last_dt = datetime.fromtimestamp(last_modify) if last_modify else None

    async for msg in client.iter_messages(entity, search='"cif": "in"', limit=None, offset_date = last_dt, reverse= True):
        if last_dt and (not msg.date or msg.date.timestamp() <= last_modify):
            continue
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
        data['data']['chats'][chat_id_hash]['time'] = time.time()

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()

    if 'masterkey' in data['data']:
        temp_data = data['data'].copy()
        del temp_data['masterkey']
        vault_ciphered = encrypt_vault(temp_data, data['data']['masterkey'])

    else:
        vault_ciphered = encrypt_vault(data['data'], data['data']['masterkey'])
    set_user_vault(username, vault_ciphered)

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
        
        if not message or not message.media or not message.document:
            raise HTTPException(status_code=404, detail="File non trovato")

        # 2. Verifica che sia un file cifrato (.dat)
        filename_attr = next((attr.file_name for attr in message.document.attributes if hasattr(attr, 'file_name')), None)
        if not filename_attr or not filename_attr.endswith('.dat'):
            raise HTTPException(status_code=400, detail="Il documento non è nel formato cifrato atteso")

        head_chunk = b""
        async for chunk in client.iter_download(message.document, limit=128 * 1024):
            head_chunk += chunk
            if len(head_chunk) > 4:
                meta_size = int.from_bytes(head_chunk[:4], byteorder='big')
                if len(head_chunk) >= 4 + meta_size:
                    break
        
        if len(head_chunk) < 4:
            raise HTTPException(status_code=400, detail="File corrotto")

        meta_size = int.from_bytes(head_chunk[:4], byteorder='big')
        try:
            metadata_plain = json.loads(head_chunk[4:4+meta_size].decode('utf-8'))
        except Exception:
            raise HTTPException(status_code=400, detail="Impossibile leggere i metadati")

        chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        chat_keys = data['data'].get('chats', {}).get(chat_id_cif, {})
        private_age_key = build_candidate_privates(chat_keys, metadata_plain.get('kids', []))
        
        if not private_age_key:
            raise HTTPException(status_code=403, detail="Non possiedi la chiave per decifrare questo file")

        inner_meta_dec = decrypt_with_age(metadata_plain['text'], private_age_key)
        if not inner_meta_dec:
            raise HTTPException(status_code=400, detail="Decifratura metadati fallita")
        
        inner_metadata = json.loads(inner_meta_dec)
        
        if is_group_chat_id(chat_id):
            _, chat_vault = get_gruppo_vault(username, chat_id, entity, data)
        else:
            _, chat_vault = await get_chat_vault(username, chat_id, client, data)

        firma_ok, _ = verify_signed_payload(
            message.sender_id, metadata_plain['id'], metadata_plain['kid'], 
            metadata_plain['kid_cif'], metadata_plain['seq'], "file", 
            metadata_plain['sign'], chat_id, data, my_id, chat_vault, 
            metadata_plain['kids'], text=inner_metadata.get('text')
        )
        
        if not firma_ok:
            raise HTTPException(status_code=403, detail="Firma non valida: il file potrebbe essere stato manomesso")

        out_filename = inner_metadata.get('filename') or 'file.bin'
        mime_type = inner_metadata.get('mime') or 'application/octet-stream'
        encrypted_data_offset = 4 + meta_size

        async def stream_decrypted_file():
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
                key_file.write(private_age_key)
                key_path = key_file.name

            proc = await asyncio.create_subprocess_exec(
                'age', '-d', '-i', key_path,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            try:
                async def feed_input():
                    try:
                        async for chunk in client.iter_download(message.document, offset=encrypted_data_offset):
                            proc.stdin.write(chunk)
                            await proc.stdin.drain()
                        proc.stdin.close()
                    except Exception:
                        proc.stdin.close()

                input_task = asyncio.create_task(feed_input())

                while True:
                    chunk = await proc.stdout.read(65536) # Chunk da 64KB
                    if not chunk:
                        break
                    yield chunk

                await input_task
                await proc.wait()
            finally:
                if os.path.exists(key_path):
                    os.remove(key_path)
                if proc.returncode != 0:
                    err = await proc.stderr.read()
                    print(f"Age error: {err.decode()}")

        return StreamingResponse(
            stream_decrypted_file(),
            media_type=mime_type,
            headers={
                'Content-Disposition': f'attachment; filename="{out_filename}"',
                'Content-Length': str(inner_metadata.get('size', '')),
                'Cache-Control': 'no-store'
            }
        )

    except Exception as e:
        print(f"Errore nel download: {e}")
        raise HTTPException(status_code=502, detail=f"Errore durante lo streaming del file: {str(e)}")