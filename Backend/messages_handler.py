from utils import is_valid_age_public_key, is_group_chat_id, build_candidate_privates, are_metadata_equals, take_file_data
from databaseInteractions import store_public_key_in_vault
from cryptography_ import decrypt_with_age
import json

async def handle_in(my_id, msg, data, entity):
    chat_id = msg.get('chat_id')
    if my_id and msg.get('sender_id') == my_id:
        msg['is_json'] = False
        msg['text'] = None
        msg['chiave'] = "Questo messaggio e' uno scambio di chiave"
        msg['is_system'] = True
        return 
    public = msg.get('json', {}).get('public')
    kid = msg.get('json', {}).get('kid')
    kid_cif = msg.get('json', {}).get('kid_cif')
    pub_sign = msg.get('json', {}).get('pub_sign')
    if not is_valid_age_public_key(public) or any(t is None for t in (public, kid, kid_cif, pub_sign)):
        msg['error'] = "questo messaggio e' stato modificato"
        msg.pop('json', None)
        msg['is_json'] = False
        return 
    store_public_key_in_vault(
        data,
        chat_id,
        msg.get('sender_id'),
        public,
        kid=kid,
        kid_cif=kid_cif,
        pub_sign=pub_sign,
        msg_date=msg.get('date'),
        is_group=is_group_chat_id(chat_id),
        group_title=getattr(entity, 'title', 'Gruppo')
    )
    
    msg['text'] = None
    msg['chiave'] = "Questo messaggio e' uno scambio di chiave"
    msg['is_system'] = True
    msg.pop('json', None)
    msg['is_json'] = False

def handle_on(msg: dict, data: dict, chat_id_cif: str, verify_sig_cb, update_seq_cb):
    text = msg['json'].get('text')
    msg_decrypted_id_caption = msg['json'].get('id')
    seq = msg['json'].get('seq')
    kid = msg['json'].get('kid')
    kid_cif = msg['json'].get('kid_cif') or msg['json'].get('kid_age')
    sign = msg['json'].get('sign')
    kids = msg['json'].get('kids')

    if any(t is None for t in (seq, kid, kid_cif, sign, text, msg_decrypted_id_caption, kids)):
        msg['error'] = "questo messaggio e' stato modificato"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    firma, sign_error = verify_sig_cb(msg.get('sender_id'), msg_decrypted_id_caption, kid, kid_cif, seq, "on", sign, kids)
    if not firma:
        msg['error'] = sign_error
        msg.pop('json', None)
        msg['is_json'] = False
        return

    chats_data = data.get('data', {}).get('chats', {})
    chat_keys = chats_data.get(chat_id_cif, {})
    private = build_candidate_privates(chat_keys, kids, kid_cif=kid_cif)

    decrypted_text = decrypt_with_age(text, private)
    if not decrypted_text:
        msg['error'] = "impossibile decifrare il messaggio"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    try:
        dic_mes = json.loads(decrypted_text)
        if dic_mes.get('cif') != "on" or not are_metadata_equals(dic_mes, msg['json']):
            msg['error'] = "questo messaggio e' stato modificato"
            msg.pop('json', None)
            msg['is_json'] = False
            return

        seq_ok, seq_error = update_seq_cb(msg.get('sender_id'), seq)
        if not seq_ok:
            msg['error'] = seq_error
            msg.pop('json', None)
            msg['is_json'] = False
            return

        msg['_secure_seq'] = seq
        msg['_secure_sender_key'] = str(msg.get('sender_id')) if msg.get('sender_id') is not None else "unknown"
        msg['text'] = dic_mes['text']
        msg['secure'] = True
        msg.pop('json', None)
        msg['is_json'] = False

    except Exception:
        msg['error'] = "errore nella lettura del messaggio"
        msg.pop('json', None)
        msg['is_json'] = False

async def handle_file(client, entity, msg: dict, data: dict, chat_id_cif: str, verify_sig_cb, update_seq_cb):
    msg['metadata_plain'], msg['encrypted_metadata'] = await take_file_data(client, entity, msg, "file")

    if not msg.get('metadata_plain') and not msg.get('encrypted_metadata'):
        msg['error'] = "Il download del messaggio non è andato a buon fine"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    msg_decrypted_id_caption = msg.get('metadata_plain', {}).get('id')
    seq = msg.get('metadata_plain', {}).get('seq')
    kid = msg.get('metadata_plain', {}).get('kid')
    kid_cif = msg.get('metadata_plain', {}).get('kid_cif')
    sign = msg.get('metadata_plain', {}).get('sign')
    kids = msg.get('metadata_plain', {}).get('kids')

    if any(t is None for t in (seq, kid, kid_cif, sign, msg_decrypted_id_caption, kids)):
        msg['error'] = "questo messaggio e' stato modificato"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    firma, sign_error = verify_sig_cb(msg.get('sender_id'), msg_decrypted_id_caption, kid, kid_cif, seq, "file", sign, kids)
    if not firma:
        msg['error'] = sign_error
        msg.pop('json', None)
        msg['is_json'] = False
        return

    chats_data = data.get('data', {}).get('chats', {})
    chat_keys = chats_data.get(chat_id_cif, {})
    private = build_candidate_privates(chat_keys, kids, kid_cif=kid_cif)

    if not msg.get('encrypted_metadata'):
        msg['error'] = "metadati cifrati mancanti"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    decrypted_text = decrypt_with_age(msg['encrypted_metadata'], private)
    if not decrypted_text:
        msg['error'] = "impossibile decifrare i metadati"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    try:
        dic_mes = json.loads(decrypted_text)
        if dic_mes.get('cif') != "file" or dic_mes != msg['metadata_plain']:
            msg['error'] = "questo messaggio e' stato modificato"
            msg.pop('json', None)
            msg['is_json'] = False
            return

        seq_ok, seq_error = update_seq_cb(msg.get('sender_id'), seq)
        if not seq_ok:
            msg['error'] = seq_error
            msg.pop('json', None)
            msg['is_json'] = False
            return

        msg['file'] = True
        msg['filename'] = dic_mes['filename']
        msg['text'] = dic_mes['text']
        msg['mime'] = dic_mes['mime']
        msg['size'] = dic_mes['size']
        msg['secure'] = True
        msg['_secure_seq'] = seq
        msg['_secure_sender_key'] = str(msg.get('sender_id')) if msg.get('sender_id') is not None else "unknown"

        msg.pop('encrypted_metadata', None)
        msg.pop('metadata_plain', None)
        msg.pop('json', None)
        msg['is_json'] = False

    except Exception:
        msg['error'] = "errore nella lettura del file"
        msg.pop('json', None)
        msg['is_json'] = False

async def handle_message(client, entity, msg: dict, data: dict, chat_id_cif: str, verify_sig_cb, update_seq_cb):
    msg['metadata_plain'], msg['encrypted_payload'] = await take_file_data(client, entity, msg, "message")

    if not msg.get('metadata_plain') and not msg.get('encrypted_payload'):
        msg['error'] = "Il download del messaggio non è andato a buon fine"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    msg_decrypted_id_caption = msg.get('metadata_plain', {}).get('id')
    seq = msg.get('metadata_plain', {}).get('seq')
    kid = msg.get('metadata_plain', {}).get('kid')
    kid_cif = msg.get('metadata_plain', {}).get('kid_cif')
    sign = msg.get('metadata_plain', {}).get('sign')
    kids = msg.get('metadata_plain', {}).get('kids')

    if any(t is None for t in (seq, kid, kid_cif, sign, msg_decrypted_id_caption, kids)):
        msg['error'] = "questo messaggio e' stato modificato"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    firma, sign_error = verify_sig_cb(msg.get('sender_id'), msg_decrypted_id_caption, kid, kid_cif, seq, "message", sign, kids)
    if not firma:
        msg['error'] = sign_error
        msg.pop('json', None)
        msg['is_json'] = False
        return

    chats_data = data.get('data', {}).get('chats', {})
    chat_keys = chats_data.get(chat_id_cif, {})
    private = build_candidate_privates(chat_keys, kids, kid_cif=kid_cif)

    decrypted_payload = decrypt_with_age(msg['encrypted_payload'], private, False)
    if not decrypted_payload:
        msg['error'] = "impossibile decifrare il payload"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    if isinstance(decrypted_payload, str):
        decrypted_payload = decrypted_payload.encode('utf-8')

    if len(decrypted_payload) >= 4:
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
                if inner_metadata != msg['metadata_plain']:
                    msg['error'] = "questo messaggio e' stato modificato"
                    msg.pop('json', None)
                    msg['is_json'] = False
                    return

                seq_ok, seq_error = update_seq_cb(msg.get('sender_id'), seq)
                if not seq_ok:
                    msg['error'] = seq_error
                    msg.pop('json', None)
                    msg['is_json'] = False
                    return

                msg['text'] = message_bytes.decode('utf-8', errors='replace')
                msg['secure'] = True
                msg['file'] = False
                msg['_secure_seq'] = seq
                msg['_secure_sender_key'] = str(msg.get('sender_id')) if msg.get('sender_id') is not None else "unknown"

                msg.pop('encrypted_payload', None)
                msg.pop('file_head', None)
                msg.pop('file_head_size', None)
                msg.pop('metadata_plain', None)
                msg.pop('media_type', None)
                msg.pop('filename', None)
                msg.pop('mime', None)
                msg.pop('size', None)
                msg.pop('json', None)
                msg['is_json'] = False
                return

    msg['error'] = "errore nella lettura del payload"
    msg.pop('json', None)
    msg['is_json'] = False
