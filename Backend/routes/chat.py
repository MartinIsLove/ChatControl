from fastapi import APIRouter, Cookie, WebSocket, WebSocketDisconnect, HTTPException
import sqlite3, hashlib, json, tempfile, os, time
from datetime import datetime
from database.sqlite import get_connection, db_lock
from config import pepper, DOWNLOAD_FAST
from databaseInteractions import store_public_key_in_vault, get_group_vault, get_chat_vault, chats_vault_update, set_user_vault
from cryptography_ import verify_signed_payload, decrypt_with_age, encrypt_vault, decrypt_file_with_age_stream
from utils import is_logged_in, is_valid_age_public_key, is_group, build_candidate_privates, set_media
from realtime import connect_socket, disconnect_socket, register_telethon_handlers, index_messages
from telethon.tl.types import MessageService, MessageActionChatCreate, MessageActionChatDeleteUser, MessageActionChatAddUser, MessageActionPinMessage
from fastapi.responses import StreamingResponse
from messages_handler import handle_in, handle_file, handle_on, handle_message
from FastTelethonhelper import fast_download

router = APIRouter()

async def stream_verified_decrypted_file(encrypted_tmp_path, encrypted_data_offset, private_age_key, sender_id, payload_kid, file_sign, chat_id, data, my_id, chat_vault,
):
    decrypted_tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_out:
            decrypted_tmp_path = tmp_out.name

        file_hash = await decrypt_file_with_age_stream(
            encrypted_tmp_path,
            decrypted_tmp_path,
            private_age_key,
            encrypted_data_offset=encrypted_data_offset,
        )

        file_sign_ok, file_sign_error = verify_signed_payload(
            data,
            chat_id,
            my_id,
            sender_id,
            None,
            payload_kid,
            None,
            None,
            None,
            file_sign,
            None,
            file_hash=file_hash,
            chat_vault=chat_vault,
        )
        if not file_sign_ok:
            raise RuntimeError(file_sign_error)

        with open(decrypted_tmp_path, 'rb') as in_f:
            while True:
                chunk = in_f.read(65536)
                if not chunk:
                    break
                yield chunk
    finally:
        if decrypted_tmp_path and os.path.exists(decrypted_tmp_path):
            try:
                file_size = os.path.getsize(decrypted_tmp_path)
                if file_size > 0:
                    with open(decrypted_tmp_path, 'r+b') as wipe_file:
                        wipe_file.write(b'\0' * file_size)
                        wipe_file.flush()
                        os.fsync(wipe_file.fileno())
            except Exception:
                pass
            os.remove(decrypted_tmp_path)
        if encrypted_tmp_path and os.path.exists(encrypted_tmp_path):
            os.remove(encrypted_tmp_path)

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
            
            '''Controlla la presenza di chat già inizializzate per poter 
               denominare come cyphered la chat, poiché sarebbe già inizializzata.'''
            
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
        if is_group(chat_id):
            _, chat_vault = get_group_vault(username, chat_id, entity, data)
        else:
            _, chat_vault = await get_chat_vault(username, chat_id, client, data)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    '''il blocco di codice che segue inizializza il partecipante/i nel caso in cui non 
       fossero già presenti nel vault'''
    if is_group(chat_id):
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
    
    '''funzione che nel caso in cui il numero di sequenza del messaggio precedente (nella history)
       dovesse essere maggiore o uguale di quello successivo'''
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

    '''funzione che controlla a ritroso nella history dei messaggi (solo 100 hit) se ci sono messaggi con numero di
       sequenza uguale a quello dei primi messaggi nella finestra per ogni utente'''
    async def has_duplicate_seq_in_history(sender_id, seq_value, current_msg_id):
        if sender_id is None:
            return False

        async for history_msg in client.iter_messages(entity, from_user=sender_id, limit=100, max_id=current_msg_id-1):
            raw_text = history_msg.message or ''

            try:
                parsed_history = json.loads(raw_text)
            except Exception:
                continue

            if not isinstance(parsed_history, dict):
                continue

            cif_flag = parsed_history.get('cif')
            if cif_flag not in ("on", "file", "message"):
                continue

            history_seq = parsed_history.get('seq')
            if isinstance(history_seq, int) and history_seq == seq_value:
                return True

        return False

    '''questa funzione prende i primi messaggi per ogni utente e li passa alla funzione superiore'''
    async def mark_replay_on_chunk(messages_list):
        oldest_by_sender = {}

        for item in reversed(messages_list):
            sender_key = item.get('_secure_sender_key')
            seq_value = item.get('_secure_seq')
            message_id = item.get('id')
            sender_id = item.get('sender_id')

            if sender_key is None or not isinstance(seq_value, int):
                continue

            #se questo sender specifico già è nel dizionario allora questo messaggio è più nuovo e non ci serve
            if sender_key in oldest_by_sender:
                continue

            #se il messaggio è già stato etichettato come errore allora non ci serve
            if item.get('error'):
                continue

            oldest_by_sender[sender_key] = {
                'sender_id': sender_id,
                'seq': seq_value,
                'message_id': message_id,
                'message_ref': item,
            }

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

            if result:
                message_ref = candidate['message_ref']
                message_ref['error'] = "questo messaggio e' un reply attack"
                message_ref.pop('secure', None)
                message_ref.pop('chiave', None)

    '''questa funzione prende il numero di sequenza maggiore del presente e lo salva nel vault'''
    def update_max_seq(sender_id, seq_value):
        nonlocal seq_dirty
        
        if is_group(chat_id):
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

        #si analizzano i messaggi di servizio, come creazione chat, un utente abbandona, ...
        if isinstance(msg, MessageService):
            action = msg.action
            if isinstance(action, MessageActionChatCreate):
                system_message = f"Gruppo creato: {action.title}"
            elif isinstance(action, MessageActionChatDeleteUser):
                left_user = getattr(action, 'user_id', None)
                left_user_name = None

                #si cerca di risolvere l'username dell'utente che ha lasciato il gruppo
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
                system_message = f"Un messaggio è stato pinnato nella chat"

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
            'system_type': system_message,
        }
        
        if msg.media:
            set_media(msg, message_data)
        
        messages.append(message_data)

    await index_messages(temp_id, chat_id, [m.get("id") for m in messages if m.get("id") is not None])

    def history_verify_sig(sender_id, msg_id_cap, kid, kid_cif, seq, flag, sign, kids, text):
        return verify_signed_payload(data, chat_id, my_id, sender_id, msg_id_cap, kid, kid_cif, seq, flag, sign, kids, text=text, chat_vault=chat_vault)

    def history_update_seq(sender_id, seq):
        update_max_seq(sender_id, seq)
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
            cif_flag = msg['json'].get('cif')

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

    await mark_replay_on_chunk(messages)
    mark_replay_in_history(messages)
    for msg in messages:
        msg.pop('_secure_seq', None)
        msg.pop('_secure_sender_key', None)


    #questo blocco aggiorna i numeri di sequenza nel vault degli utenti, solo se è stato modificato
    if seq_dirty:
        try:
            if is_group(chat_id):
                latest_insert_new_vault, latest_chat_vault = get_group_vault(username, chat_id, entity, data)
                
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

    chat_group = is_group(chat_id)
    chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    #prende time dal dizionario in ram, il quale rappresenta l'ultima ricerca per le chiavi nella chat
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

        cif_flag = parsed.get('cif')
        public = parsed.get('public')
        kid = parsed.get('kid')
        kid_cif = parsed.get('kid_cif')
        pub_sign = parsed.get('pub_sign')

        if cif_flag != "in" or not public or not is_valid_age_public_key(public):
            continue

        store_public_key_in_vault(
            data,
            chat_id,
            msg.sender_id,
            public,
            kid=kid,
            kid_cif=kid_cif,
            pub_sign=pub_sign,
            chat_group=chat_group,
            group_title=getattr(entity, 'title', 'Gruppo')
        )
        data['data']['chats'][chat_id_hash]['time'] = time.time()

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()

    if 'masterkey' in data['data']:
        temp_data = data['data'].copy()
        del temp_data['masterkey']
        vault_encrypted = encrypt_vault(temp_data, data['data']['masterkey'])

    else:
        vault_encrypted = encrypt_vault(data['data'], data['data']['masterkey'])
    set_user_vault(username, vault_encrypted)

    return {"status":"ok"}

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

        if message.document:
            filename_attr = next((attr.file_name for attr in message.document.attributes if hasattr(attr, 'file_name')), None)
            if filename_attr and filename_attr.endswith('.dat'):
                raise HTTPException(
                    status_code=403,
                    detail="File cifrato: usa il download sicuro con verifica integrita'"
                )
        
        async def stream_media_chunks():
            async for chunk in client.iter_download(message.media, request_size=64 * 1024):
                yield chunk
        
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
            stream_media_chunks(),
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
    encrypted_tmp_path = None
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

        filename_attr = next((attr.file_name for attr in message.document.attributes if hasattr(attr, 'file_name')), None)
        if not filename_attr or not filename_attr.endswith('.dat'):
            raise HTTPException(status_code=400, detail="Il documento non è nel formato cifrato atteso")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as tmp_enc:
            encrypted_tmp_path = tmp_enc.name

        document_size = getattr(message.document, 'size', 0) or 0
        if document_size > DOWNLOAD_FAST:
            download_folder = os.path.dirname(encrypted_tmp_path) + os.sep
            downloaded_path = await fast_download(client, message, download_folder=download_folder)
            if downloaded_path != encrypted_tmp_path:
                os.replace(downloaded_path, encrypted_tmp_path)
            
        else:
            await client.download_media(message, file=encrypted_tmp_path)

        with open(encrypted_tmp_path, 'rb') as encrypted_in:
            prefix = encrypted_in.read(4)
            if len(prefix) < 4:
                raise HTTPException(status_code=400, detail="File corrotto")
            meta_size = int.from_bytes(prefix, byteorder='big')
            metadata_bytes = encrypted_in.read(meta_size)

        if len(metadata_bytes) != meta_size:
            raise HTTPException(status_code=400, detail="File corrotto")

        try:
            metadata_plain = json.loads(metadata_bytes.decode('utf-8'))
        except Exception:
            raise HTTPException(status_code=400, detail="Impossibile leggere i metadati")

        chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        chat_keys = data['data'].get('chats', {}).get(chat_id_cif, {})
        msg_id = metadata_plain.get('id')
        seq = metadata_plain.get('seq')
        kid = metadata_plain.get('kid')
        kid_cif = metadata_plain.get('kid_cif')
        sign = metadata_plain.get('sign')
        kids = metadata_plain.get('kids')
        encrypted_inner_metadata = metadata_plain.get('text')

        if any(t is None for t in (seq, kid, kid_cif, sign, msg_id, kids, encrypted_inner_metadata)):
            raise HTTPException(status_code=400, detail="Metadati mancanti o incompleti")

        private_age_key = build_candidate_privates(chat_keys, kids)

        if not private_age_key:
            raise HTTPException(status_code=403, detail="Non possiedi la chiave per decifrare questo file")

        inner_meta_dec = decrypt_with_age(encrypted_inner_metadata, private_age_key)
        if not inner_meta_dec:
            raise HTTPException(status_code=400, detail="Decifratura metadati fallita")

        try:
            inner_metadata = json.loads(inner_meta_dec)
        except Exception:
            raise HTTPException(status_code=400, detail="Impossibile leggere i metadati interni")

        if (inner_metadata.get('cif') != "file" or
            inner_metadata.get('id') != msg_id or
            inner_metadata.get('seq') != seq or
            inner_metadata.get('kid') != kid or
            inner_metadata.get('sign') != sign):
            raise HTTPException(status_code=400, detail="Metadati incongruenti o manomessi")

        file_sign = inner_metadata.get('file_sign')
        if not file_sign:
            raise HTTPException(status_code=400, detail="Metadati file incompleti: firma finale assente")
        
        if is_group(chat_id):
            _, chat_vault = get_group_vault(username, chat_id, entity, data)
        else:
            _, chat_vault = await get_chat_vault(username, chat_id, client, data)

        firma_ok, _ = verify_signed_payload(
            data=data,
            chat_id=chat_id,
            my_id=my_id,
            sender_id=message.sender_id,
            payload_id=metadata_plain['id'],
            payload_kid=metadata_plain['kid'],
            payload_kid_cif=metadata_plain['kid_cif'],
            payload_seq=metadata_plain['seq'],
            payload_cif="file",
            payload_sign=metadata_plain['sign'],
            kids=metadata_plain['kids'],
            text=inner_metadata.get('text'),
            chat_vault=chat_vault,
        )
        
        if not firma_ok:
            raise HTTPException(status_code=403, detail="Firma metadati non valida: il file potrebbe essere stato manomesso")
        out_filename = inner_metadata.get('filename') or 'file.bin'
        mime_type = inner_metadata.get('mime') or 'application/octet-stream'
        encrypted_data_offset = 4 + meta_size

        return StreamingResponse(
            stream_verified_decrypted_file(
                encrypted_tmp_path,
                encrypted_data_offset,
                private_age_key,
                message.sender_id,
                metadata_plain['kid'],
                file_sign,
                chat_id,
                data,
                my_id,
                chat_vault,
            ),
            media_type=mime_type,
            headers={
                'Content-Disposition': f'attachment; filename="{out_filename}"',
                'Content-Length': str(inner_metadata.get('size', '')),
                'Cache-Control': 'no-store'
            }
        )

    except HTTPException:
        if encrypted_tmp_path and os.path.exists(encrypted_tmp_path):
            os.remove(encrypted_tmp_path)
        raise
    except Exception as e:
        if encrypted_tmp_path and os.path.exists(encrypted_tmp_path):
            os.remove(encrypted_tmp_path)
        raise HTTPException(status_code=502, detail=f"Errore durante lo streaming del file: {str(e)}")