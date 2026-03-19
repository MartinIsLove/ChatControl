import asyncio, base64, subprocess, tempfile, hashlib, sqlite3, json, io, os
from fastapi import WebSocket, HTTPException
from telethon import events, utils
from telethon.tl.types import PeerChannel, UpdateDeleteChannelMessages, UpdateDeleteMessages
from config import pepper
from database.sqlite import get_connection, db_lock
from cryptography_ import decrypt_with_age, decrypt_vault, decrypt_vault, verify_message_sign, calculate_message_sign, encrypt_vault
from databaseInteractions import store_public_key_in_vault
from utils import  login_cache, is_valid_age_public_key, set_media, is_logged_in, build_candidate_privates, take_file_data, are_metadata_equals

_active_connections = {}
_connections_lock = asyncio.Lock()

_message_index = {}
_message_index_lock = asyncio.Lock()
_MAX_INDEX_PER_CHAT = 3000


def _is_group_chat_id(chat_id: int) -> bool:
    try:
        return int(chat_id) < 0
    except Exception:
        return False


def _get_remote_signing_keys(user_data, chat_id: int, sender_id: int | None) -> dict:
    if not user_data:
        return {}

    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            if _is_group_chat_id(chat_id):
                cursor.execute(
                    """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    return {}
                vault_deciphered = decrypt_vault(risultato[0], user_data['data']['masterkey'])
                partecipanti = vault_deciphered.get('partecipanti', {})
                participant = partecipanti.get(str(sender_id)) if isinstance(partecipanti, dict) else None
                if participant is None and isinstance(partecipanti, dict):
                    participant = partecipanti.get(sender_id)
                signing_keys = participant.get('chiavi_firma', {}) if isinstance(participant, dict) else {}
            else:
                cursor.execute(
                    """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    return {}
                vault_deciphered = decrypt_vault(risultato[0], user_data['data']['masterkey'])
                signing_keys = vault_deciphered.get('chiavi_firma', {}) if isinstance(vault_deciphered, dict) else {}
    except Exception:
        return {}

    return signing_keys if isinstance(signing_keys, dict) else {}


def _verify_signed_payload(
    user_data,
    chat_id: int,
    chat_id_cif: str,
    my_id: int | None,
    sender_id: int | None,
    payload_id,
    payload_kid,
    payload_kid_cif,
    payload_seq,
    payload_cif,
    payload_sign,
    kids,
) -> tuple[bool, str]:

    if my_id and sender_id == my_id:
        local_kid_map = user_data.get('data', {}).get('chats', {}).get(chat_id_cif, {}).get('kid', {})
        sign_private = local_kid_map.get(payload_kid) if isinstance(local_kid_map, dict) else None
        if not sign_private:
            return False, "chiave di firma locale non disponibile"
        try:
            expected_sign = calculate_message_sign(sign_private, payload_seq, payload_kid, payload_kid_cif, payload_id, payload_cif, kids)
        except ValueError:
            return False, "questo messaggio e' stato modificato"
        return (payload_sign == expected_sign), "questo messaggio e' stato modificato"

    remote_signing_keys = _get_remote_signing_keys(user_data, chat_id, sender_id)
    pub_sign = remote_signing_keys.get(payload_kid) if isinstance(remote_signing_keys, dict) else None
    if not pub_sign:
        return False, "chiave di firma mittente non disponibile"
    try:
        return verify_message_sign(pub_sign, payload_seq, payload_kid, payload_kid_cif, payload_id, payload_cif, payload_sign, kids), "questo messaggio e' stato modificato"
    except ValueError:
        return False, "questo messaggio e' stato modificato"


def _validate_and_store_realtime_seq(user_data, chat_id: int, sender_id: int | None, seq) -> tuple[bool, str | None]:
    if not isinstance(seq, int):
        return False, "questo messaggio e' stato modificato"

    if sender_id is None:
        return False, "questo messaggio e' stato modificato"

    if not user_data:
        return False, "utente non disponibile"

    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    is_group = _is_group_chat_id(chat_id)

    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            if is_group:
                cursor.execute(
                    """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                    (username, chat_id_cif)
                )
                result = cursor.fetchone()
                if not result or not result[0]:
                    return False, "chiave di cifratura mittente non disponibile"

                vault_deciphered = decrypt_vault(result[0], user_data['data']['masterkey'])
                partecipants = vault_deciphered.get('partecipanti')
                if not isinstance(partecipants, dict):
                    partecipants = {}
                    vault_deciphered['partecipanti'] = partecipants

                sender_key = str(sender_id)
                participant_data = partecipants.get(sender_key)
                if participant_data is None:
                    participant_data = partecipants.get(sender_id)
                if not isinstance(participant_data, dict):
                    participant_data = {}

                current_seq = participant_data.get('seq') if isinstance(participant_data.get('seq'), int) else None
                if current_seq is not None and seq <= current_seq:
                    return False, "questo messaggio e' un reply attack"

                participant_data['seq'] = seq
                partecipants[sender_key] = participant_data

                updated_vault = encrypt_vault(vault_deciphered, user_data['data']['masterkey'])
                cursor.execute(
                    """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                    (updated_vault, username, chat_id_cif)
                )
            else:
                cursor.execute(
                    """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                result = cursor.fetchone()
                if not result or not result[0]:
                    return False, "chiave di cifratura mittente non disponibile"

                vault_deciphered = decrypt_vault(result[0], user_data['data']['masterkey'])
                current_seq = vault_deciphered.get('seq') if isinstance(vault_deciphered.get('seq'), int) else None
                if current_seq is not None and seq <= current_seq:
                    return False, "questo messaggio e' un reply attack"

                vault_deciphered['seq'] = seq
                updated_vault = encrypt_vault(vault_deciphered, user_data['data']['masterkey'])
                cursor.execute(
                    """UPDATE contatti SET vault = ? WHERE proprietario = ? AND contatto_id = ?""",
                    (updated_vault, username, chat_id_cif)
                )

            conn.commit()
    except Exception:
        return False, "errore nella persistenza del numero di sequenza"

    return True, None


async def _remove_user_from_vault(temp_id: str, chat_id: int, user_id: int | None):
    user_data = login_cache.get(temp_id)
    if not user_data:
        return

    if user_id is not None and not _is_group_chat_id(chat_id):
        if str(user_id) != str(chat_id):
            return

    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    is_group = _is_group_chat_id(chat_id)

    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            if is_group:
                cursor.execute(
                    """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                    (username, chat_id_cif)
                )
                result = cursor.fetchone()
                if not result or not result[0]:
                    return
                vault_deciphered = decrypt_vault(result[0], user_data['data']['masterkey'])
                partecipants = vault_deciphered.get('partecipanti')
                if not partecipants or str(user_id) not in partecipants:
                    return
                del partecipants[str(user_id)]
                ciphered_vault = encrypt_vault(vault_deciphered, user_data['data']['masterkey'])
                cursor.execute(
                    """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                    (ciphered_vault, username, chat_id_cif)
                )
                conn.commit()
            else:
                cursor.execute(
                    """DELETE FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                conn.commit()
    except sqlite3.Error as error:
        return

#crea una struttura con al suo interno l'id utente, connesso ad ogni chat con un set ed una lista di id dei messaggi con eventi (la lista e' ordinata)
#serve solo per alcuni raw update eliminazioni in chat singole per esempio
async def index_messages(temp_id: str, chat_id: int, mess_ids: list[int]):
    if not mess_ids:
        return
    async with _message_index_lock:
        user_map = _message_index.setdefault(temp_id, {})
        chat_map = user_map.setdefault(chat_id, {"ids": set(), "order": []})
        ids_set = chat_map["ids"]
        order = chat_map["order"]
        for mid in mess_ids:
            if mid is None:
                continue
            if mid in ids_set:
                continue
            ids_set.add(mid)
            order.append(mid)
        if len(order) > _MAX_INDEX_PER_CHAT:
            overflow = len(order) - _MAX_INDEX_PER_CHAT
            for _ in range(overflow):
                old = order.pop(0)
                ids_set.discard(old)


async def drop_message_ids(temp_id: str, chat_id: int, message_ids: list[int]):
    if not message_ids:
        return
    async with _message_index_lock:
        user_map = _message_index.get(temp_id)
        if not user_map:
            return
        chat_map = user_map.get(chat_id)
        if not chat_map:
            return
        ids_set = chat_map["ids"]
        order = chat_map["order"]
        for mid in message_ids:
            ids_set.discard(mid)
        if order:
            chat_map["order"] = [mid for mid in order if mid in ids_set]


async def resolve_chat_id_for_deleted(temp_id: str, mess_ids: list[int]) -> int | None:
    if not mess_ids:
        return None
    async with _message_index_lock:
        user_map = _message_index.get(temp_id)
        if not user_map:
            return None
        ids = set(mid for mid in mess_ids if mid is not None)
        if not ids:
            return None
        candidates = []
        for chat_id, chat_map in user_map.items():
            if ids.issubset(chat_map["ids"]):
                candidates.append(chat_id)
        if len(candidates) == 1:
            return candidates[0]
        return None


def _serialize_message(msg):
    mess_data = {
        "id": msg.id,
        "chat_id": msg.chat_id,
        "text": msg.message or "",
        "date": msg.date if msg.date else None,
        "sender_id": msg.sender_id,
        "out": msg.out,
        "reply_to": msg.reply_to.reply_to_msg_id if msg.reply_to else None,
    }
    if msg.media:
        set_media(msg, mess_data)

    return mess_data


async def connect_socket(temp_id: str, chat_id: int, websocket: WebSocket):
    await websocket.accept()
    async with _connections_lock:
        user_map = _active_connections.setdefault(temp_id, {})
        sockets = user_map.setdefault(chat_id, set())
        sockets.add(websocket)


async def disconnect_socket(temp_id: str, chat_id: int, websocket: WebSocket):
    async with _connections_lock:
        user_map = _active_connections.get(temp_id)
        if not user_map:
            return
        sockets = user_map.get(chat_id)
        if not sockets:
            return
        sockets.discard(websocket)
        if not sockets:
            user_map.pop(chat_id, None)
        if not user_map:
            _active_connections.pop(temp_id, None)


async def broadcast_event(temp_id: str, chat_id: int, payload: dict):
    async with _connections_lock:
        sockets = list(_active_connections.get(temp_id, {}).get(chat_id, set()))

    if not sockets:
        return

    dead = []
    for ws in sockets:
        try:
     
            if payload.get('message') and payload.get('message').get('date'):
                payload['message']['date']= payload['message']['date'].isoformat()
        
                
            await ws.send_json(payload)
        except Exception as e:
            dead.append(ws)

    for ws in dead:
        await disconnect_socket(temp_id, chat_id, ws)


def register_telethon_handlers(client, temp_id: str, login_session: str):
    if getattr(client, "_cc_handlers_added", False):
        return

    async def handle_new_message(event):
        try:
            entity = await client.get_entity(event.chat_id)
        except:
            return 
        temp_id, data = is_logged_in(login_session, False)
        me = await client.get_me()
        my_id = me.id if me else None
        msg = _serialize_message(event.message)
        sender = await event.message.get_sender()
        msg['sender_username'] = getattr(sender, 'username', None) if sender else None
        chat_id_cif = hashlib.sha256(pepper.encode() + str(event.chat_id).encode()).hexdigest()

        if not event.chat_id:
            return
        if event.message and event.message.id:
            await index_messages(temp_id, event.chat_id, [event.message.id])
        if event.message:
            
            text = event.message.message or ""
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    msg['json'] = parsed
                    msg['is_json'] = True
                else:
                    msg['is_json'] = False
            except Exception:
                msg['is_json'] = False
                parsed = None

            if msg['is_json'] == True:
                cif_flag = parsed.get("CIF") or parsed.get("cif")
                if cif_flag == "in":
                    if my_id and msg.get('sender_id') == my_id:
                        msg['is_json'] = False
                        msg['text'] = None
                        msg['chiave'] = "Questo messaggio e' uno scambio di chiave"
                        msg['is_system'] = True
                        payload = {
                            "event_type": "new",
                            "chat_id": event.chat_id,
                            "message": msg,
                        }
                        await broadcast_event(temp_id, event.chat_id, payload)
                        return

                    public = parsed.get("public")
                    kid = parsed.get('kid')
                    kid_cif = parsed.get('kid_cif')
                    pub_sign = parsed.get('pub_sign')
                    if not is_valid_age_public_key(public) or any(t is None for t in (public, kid, kid_cif, pub_sign)):
                        msg['error'] = "Questo messaggio è stato modificato"
                        if 'json' in msg:
                            del msg['json']
                        msg['is_json'] = False
                        payload = {
                            "event_type": "new",
                            "chat_id": event.chat_id,
                            "message": msg,
                        }
                        await broadcast_event(temp_id, event.chat_id, payload)
                        return

                    user_data = login_cache.get(temp_id)
                    if user_data:
                        store_public_key_in_vault(
                            user_data,
                            event.chat_id,
                            event.message.sender_id,
                            public,
                            kid=kid,
                            kid_cif=kid_cif,
                            pub_sign=pub_sign,
                            msg_date=msg.get('date'),
                            is_group=_is_group_chat_id(event.chat_id),
                            group_title=getattr(event.chat, "title", "Gruppo")
                        )
                    msg['text'] = None
                    msg['chiave'] = "Questo messaggio e' uno scambio di chiave"
                    msg['is_system'] = True
                
                if cif_flag == "on":
                    text = msg['json'].get('text')
                    id_message = msg['json'].get('id')
                    seq = msg['json'].get('seq')
                    kid = msg['json'].get('kid')
                    kid_cif = msg['json'].get('kid_cif')
                    sign = msg['json'].get('sign')
                    kids = msg['json'].get('kids')

                    if any(t is None for t in (seq, kid, kid_cif, sign, text, id_message, kids)):
                        msg['error'] = "Questo messaggio è stato modificato"
                        if 'json' in msg:
                            del msg['json']
                        msg['is_json'] = False
                        payload = {
                            "event_type": "new",
                            "chat_id": event.chat_id,
                            "message": msg,
                        }
                        await broadcast_event(temp_id, event.chat_id, payload)
                        return

                    valid_sign, sign_error = _verify_signed_payload(
                        data,
                        event.chat_id,
                        chat_id_cif,
                        my_id,
                        msg.get('sender_id'),
                        id_message,
                        kid,
                        kid_cif,
                        seq,
                        cif_flag,
                        sign,
                        kids,
                    )

                    if not valid_sign:
                        msg['error'] = sign_error
                        if 'json' in msg:
                            del msg['json']
                        msg['is_json'] = False
                        payload = {
                            "event_type": "new",
                            "chat_id": event.chat_id,
                            "message": msg,
                        }
                        await broadcast_event(temp_id, event.chat_id, payload)
                        return

                    chats_data = data['data'].get('chats', {})
                    chat_keys = chats_data.get(chat_id_cif, {})
                    private = build_candidate_privates(chat_keys, kids, kid_cif=kid_cif)

                    decr_text = decrypt_with_age(text, private)
                                            
                    if decr_text:
                        try:
                            mess_dic = json.loads(decr_text)
                            
                            if mess_dic['cif'] == "on":
                                equals = are_metadata_equals(mess_dic, msg['json'])
                                if not equals:
                                    msg['error'] = "questo messaggio e' stato modificato"
                                    if 'json' in msg:
                                        del msg['json']
                                    msg['is_json'] = False
                                    payload = {
                                        "event_type": "new",
                                        "chat_id": event.chat_id,
                                        "message": msg,
                                    }
                                    await broadcast_event(temp_id, event.chat_id, payload)
                                    return

                                seq_ok, seq_error = _validate_and_store_realtime_seq(
                                    data,
                                    event.chat_id,
                                    msg.get('sender_id'),
                                    seq,
                                )
                                if not seq_ok:
                                    msg['error'] = seq_error
                                    if 'json' in msg:
                                        del msg['json']
                                    msg['is_json'] = False
                                    payload = {
                                        "event_type": "new",
                                        "chat_id": event.chat_id,
                                        "message": msg,
                                    }
                                    await broadcast_event(temp_id, event.chat_id, payload)
                                    return
                            
                                
                                msg['text'] = mess_dic['text']
                                msg['secure'] = True

                                
                                if 'json' in msg:
                                    del msg['json']
                                msg['is_json'] = False
                            else:
                                msg['error'] = "questo messaggio e' stato modificato"
                                if 'json' in msg:
                                    del msg['json']
                                msg['is_json'] = False
                        except Exception:
                            raise HTTPException(status_code=500)

                if cif_flag == "message":
                    try:
                        
                        msg['metadata_plain'], msg['encrypted_payload'] = await take_file_data(client, entity, msg, cif_flag)

                        if msg['metadata_plain'] == None and msg['encrypted_payload'] == None:
                            msg['error'] = "Il download del messaggio non è andato a buon fine"
                            if 'json' in msg:
                                del msg['json']
                            msg['is_json'] = False
                            payload = {
                                "event_type": "new",
                                "chat_id": event.chat_id,
                                "message": msg,
                            }
                            await broadcast_event(temp_id, event.chat_id, payload)
                            return

                        id_message = msg.get('metadata_plain', {}).get('id')
                        seq = msg.get('metadata_plain', {}).get('seq')
                        kid = msg.get('metadata_plain', {}).get('kid')
                        kid_cif = msg.get('metadata_plain', {}).get('kid_cif')
                        sign = msg.get('metadata_plain', {}).get('sign')
                        kids = msg.get('metadata_plain', {}).get('kids')

                        if any(t is None for t in (seq, kid, kid_cif, sign, id_message, kids)):
                            msg['error'] = "Questo messaggio è stato modificato"
                            if 'json' in msg:
                                del msg['json']
                            msg['is_json'] = False
                            payload = {
                                "event_type": "new",
                                "chat_id": event.chat_id,
                                "message": msg,
                            }
                            await broadcast_event(temp_id, event.chat_id, payload)
                            return

                        valid_sign, sign_error = _verify_signed_payload(
                            data,
                            event.chat_id,
                            chat_id_cif,
                            my_id,
                            msg.get('sender_id'),
                            id_message,
                            kid,
                            kid_cif,
                            seq,
                            cif_flag,
                            sign,
                            kids,
                        )
                        if not valid_sign:
                            msg['error'] = sign_error
                            if 'json' in msg:
                                del msg['json']
                            msg['is_json'] = False
                            payload = {
                                "event_type": "new",
                                "chat_id": event.chat_id,
                                "message": msg,
                            }
                            await broadcast_event(temp_id, event.chat_id, payload)
                            return

                        chats_data = data['data'].get('chats', {})
                        chat_keys = chats_data.get(chat_id_cif, {})
                        private = build_candidate_privates(chat_keys, kids, kid_cif=kid_cif)

                        decrypted_payload = decrypt_with_age(msg['encrypted_payload'], private, False)
                        
                        if decrypted_payload:
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

                                    if msg['metadata_plain'] != inner_metadata:
                                        msg['error'] = "questo messaggio e' stato modificato"
                                        if 'json' in msg:
                                            del msg['json']
                                        msg['is_json'] = False
                                        payload = {
                                            "event_type": "new",
                                            "chat_id": event.chat_id,
                                            "message": msg,
                                        }
                                        await broadcast_event(temp_id, event.chat_id, payload)
                                        return

                                    seq_ok, seq_error = _validate_and_store_realtime_seq(
                                        data,
                                        event.chat_id,
                                        msg.get('sender_id'),
                                        seq,
                                    )
                                    if not seq_ok:
                                        msg['error'] = seq_error
                                        if 'json' in msg:
                                            del msg['json']
                                        msg['is_json'] = False
                                        payload = {
                                            "event_type": "new",
                                            "chat_id": event.chat_id,
                                            "message": msg,
                                        }
                                        await broadcast_event(temp_id, event.chat_id, payload)
                                        return
                                
                                    msg['text'] = message_bytes.decode('utf-8', errors='replace')

                                    if 'json' in msg:
                                        del msg['json']
                                    msg['is_json'] = False
                                    msg['secure'] = True
                                    msg['file'] = False

                                    msg.pop('encrypted_payload', None)
                                    msg.pop('file_head', None)
                                    msg.pop('file_head_size', None)
                                    msg.pop('metadata_plain', None)

                                    msg.pop('media_type', None)
                                    msg.pop('filename', None)
                                    msg.pop('mime', None)
                                    msg.pop('size', None)
                    except Exception as e:
                        raise HTTPException(status_code=500, detail=f'errore nella gestione di un messaggio in tempo reale: {e}')
        
                if cif_flag == "file":
                    
                    msg['metadata_plain'], msg['encrypted_metadata'] = await take_file_data(client, entity, msg, cif_flag)

                    if msg.get('metadata_plain') is None and msg.get('encrypted_metadata') is None:
                        msg['error'] = "Il download del messaggio non è andato a buon fine"
                        if 'json' in msg:
                            del msg['json']
                        msg['is_json'] = False
                        payload = {
                            "event_type": "new",
                            "chat_id": event.chat_id,
                            "message": msg,
                        }
                        await broadcast_event(temp_id, event.chat_id, payload)
                        return

                    id_message = msg.get('metadata_plain', {}).get('id')
                    seq = msg.get('metadata_plain', {}).get('seq')
                    kid = msg.get('metadata_plain', {}).get('kid')
                    kid_cif = msg.get('metadata_plain', {}).get('kid_cif')
                    sign = msg.get('metadata_plain', {}).get('sign')
                    kids = msg.get('metadata_plain', {}).get('kids')

                    if any(t is None for t in (seq, kid, kid_cif, sign, id_message, kids)):
                        msg['error'] = "Questo messaggio è stato modificato"
                        if 'json' in msg:
                            del msg['json']
                        msg['is_json'] = False
                        payload = {
                            "event_type": "new",
                            "chat_id": event.chat_id,
                            "message": msg,
                        }
                        await broadcast_event(temp_id, event.chat_id, payload)
                        return

                    valid_sign, sign_error = _verify_signed_payload(
                        data,
                        event.chat_id,
                        chat_id_cif,
                        my_id,
                        msg.get('sender_id'),
                        id_message,
                        kid,
                        kid_cif,
                        seq,
                        cif_flag,
                        sign,
                        kids,
                    )
                    if not valid_sign:
                        msg['error'] = sign_error
                        if 'json' in msg:
                            del msg['json']
                        msg['is_json'] = False
                        payload = {
                            "event_type": "new",
                            "chat_id": event.chat_id,
                            "message": msg,
                        }
                        await broadcast_event(temp_id, event.chat_id, payload)
                        return
        
                    chats_data = data['data'].get('chats', {})
                    chat_keys = chats_data.get(chat_id_cif, {})
                    private = build_candidate_privates(chat_keys, kids, kid_cif=kid_cif)

                    decr_text = None
                    if msg.get('encrypted_metadata'):
                        decr_text = decrypt_with_age(msg['encrypted_metadata'], private)

                    if decr_text:
                        try:
                            mess_dic = json.loads(decr_text)
                            if mess_dic['cif'] == "file":
                                if mess_dic != msg['metadata_plain']:
                                        msg['error'] = "questo messaggio e' stato modificato"
                                        if 'json' in msg:
                                            del msg['json']
                                        msg['is_json'] = False
                                        payload = {
                                            "event_type": "new",
                                            "chat_id": event.chat_id,
                                            "message": msg,
                                        }
                                        await broadcast_event(temp_id, event.chat_id, payload)
                                        return

                                seq_ok, seq_error = _validate_and_store_realtime_seq(
                                    data,
                                    event.chat_id,
                                    msg.get('sender_id'),
                                    seq,
                                )
                                if not seq_ok:
                                    msg['error'] = seq_error
                                    if 'json' in msg:
                                        del msg['json']
                                    msg['is_json'] = False
                                    payload = {
                                        "event_type": "new",
                                        "chat_id": event.chat_id,
                                        "message": msg,
                                    }
                                    await broadcast_event(temp_id, event.chat_id, payload)
                                    return
                                
                                msg['file'] = True
                                msg['filename'] = mess_dic['filename']
                                msg['text'] = mess_dic['text']
                                msg['mime'] = mess_dic['mime']
                                msg['size'] = mess_dic['size']
                                msg['secure'] = True
                                
                                msg.pop('encrypted_metadata', None)
                                msg.pop('metadata_plain', None)

                                if 'json' in msg:
                                    del msg['json']
                                msg['is_json'] = False
                            else:
                                msg['error'] = "questo messaggio e' stato modificato"
                                if 'json' in msg:
                                    del msg['json']
                                msg['is_json'] = False
                        except Exception:
                            raise HTTPException(status_code=500)

        payload = {
            "event_type": "new",
            "chat_id": event.chat_id,
            "message": msg,
        }
        await broadcast_event(temp_id, event.chat_id, payload)
        return

    async def handle_edited_message(event):
        if not event.chat_id:
            return
        if event.message and event.message.id:
            await index_messages(temp_id, event.chat_id, [event.message.id])
        message_data=_serialize_message(event.message)
        payload = {
            "event_type": "edited",
            "chat_id": event.chat_id,
            "message": message_data,
        }
        await broadcast_event(temp_id, event.chat_id, payload)

    async def handle_deleted_message(event):
        message_ids = list(event.deleted_ids or [])
        if not message_ids:
            return
        chat_id = getattr(event, "chat_id", None)
        if not chat_id:
            peer = getattr(event, "peer_id", None)
            if peer is not None:
                try:
                    chat_id = utils.get_peer_id(peer)
                except Exception:
                    chat_id = None
        if not chat_id:
            chat_id = await resolve_chat_id_for_deleted(temp_id, message_ids)
        if not chat_id:
            return
        await drop_message_ids(temp_id, chat_id, message_ids)
        
        payload = {
            "event_type": "deleted",
            "chat_id": chat_id,
            "message_ids": message_ids,
        }
        await broadcast_event(temp_id, chat_id, payload)

    async def handle_raw_update(event):
        update = getattr(event, "update", event)
        if isinstance(update, UpdateDeleteChannelMessages):
            chat_id = utils.get_peer_id(PeerChannel(update.channel_id))
            mess_ids = list(update.messages or [])
            await drop_message_ids(temp_id, chat_id, mess_ids)
            payload = {
                "event_type": "deleted",
                "chat_id": chat_id,
                "message_ids": mess_ids,
            }
            await broadcast_event(temp_id, chat_id, payload)
        elif isinstance(update, UpdateDeleteMessages):
            mess_ids = list(update.messages or [])
            if not mess_ids:
                return
            chat_id = await resolve_chat_id_for_deleted(temp_id, mess_ids)
            if not chat_id:
                return
            await drop_message_ids(temp_id, chat_id, mess_ids)
            payload = {
                "event_type": "deleted",
                "chat_id": chat_id,
                "message_ids": mess_ids,
            }
            await broadcast_event(temp_id, chat_id, payload)

    async def handle_chat_action(event):
        if not event.chat_id:
            return
        if not (getattr(event, "user_left", False) or getattr(event, "user_kicked", False)):
            return
        user_ids = []
        if getattr(event, "user_id", None):
            user_ids.append(event.user_id)
        elif getattr(event, "user_ids", None):
            user_ids.extend(list(event.user_ids))

        for uid in user_ids:
            await _remove_user_from_vault(temp_id, event.chat_id, uid)

    client.add_event_handler(handle_new_message, events.NewMessage())
    client.add_event_handler(handle_edited_message, events.MessageEdited())
    client.add_event_handler(handle_deleted_message, events.MessageDeleted())
    client.add_event_handler(handle_raw_update, events.Raw())
    client.add_event_handler(handle_chat_action, events.ChatAction())
    client._cc_handlers_added = True
