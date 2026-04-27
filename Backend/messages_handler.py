from utils import is_valid_age_public_key, is_group, build_candidate_privates, are_metadata_equals, take_file_data
from databaseInteractions import store_public_key_in_vault, get_group_vault, get_chat_vault
from cryptography_ import decrypt_with_age, verify_message_sign
import json, hashlib
from config import pepper

async def handle_in(my_id, msg, data, entity):
    chat_id = msg.get('chat_id')
    sender_id = msg.get('sender_id')

    if my_id and sender_id == my_id:
        msg['is_json'] = False
        msg['text'] = None
        msg['chiave'] = "Questo messaggio e' uno scambio di chiave"
        msg['is_system'] = True
        return 
    
    json_data = msg.get('json', {})
    public = json_data.get('public')
    kid = json_data.get('kid')
    kid_cif = json_data.get('kid_cif')
    pub_sign = json_data.get('pub_sign')
    ikey = json_data.get('ikey')
    sign = json_data.get('sign')
    
    if not is_valid_age_public_key(public) or any(t is None for t in (public, kid, kid_cif, pub_sign)):
        msg['error'] = "questo messaggio e' stato modificato (campi base mancanti)"
        msg.pop('json', None)
        msg['is_json'] = False
        return 

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    group_chat = is_group(chat_id)
    saved_ikey = None
    known_kids =[]

    try:
        if group_chat:
            _, chat_vault = get_group_vault(username, chat_id, entity, data)
            sender_str = str(sender_id)
            participant = chat_vault.get('partecipanti', {}).get(sender_str)
            if not isinstance(participant, dict):
                participant = chat_vault.get('partecipanti', {}).get(sender_id, {})
                
            saved_ikey = participant.get('ikey')
            chiavi_map = participant.get('chiavi_cif', {})
        else:
            _, chat_vault = await get_chat_vault(username, chat_id, data['client'], data)
            saved_ikey = chat_vault.get('ikey')
            chiavi_map = chat_vault.get('chiavi_cif', {})
            
        if isinstance(chiavi_map, dict):
            known_kids = list(chiavi_map.keys())
    except Exception:
        saved_ikey = None
        known_kids =[]

    if not saved_ikey:
        if not ikey:
            msg['error'] = "Chiave di identita' (ikey) mancante. Possibile manomissione."
            msg.pop('json', None)
            msg['is_json'] = False
            return
        key_to_save = ikey
    else:
        is_known_key = (kid_cif in known_kids)

        if not is_known_key:
            if not sign:
                msg['error'] = "Firma di identita' mancante per le nuove chiavi. Rotazione negata."
                msg.pop('json', None)
                msg['is_json'] = False
                return
            
            try:
                is_valid = verify_message_sign(
                    saved_ikey, 
                    sign, 
                    public, 
                    kid, 
                    kid_cif, 
                    pub_sign, 
                    identity=True
                )
            except Exception:
                is_valid = False

            if not is_valid:
                msg['error'] = "Firma di identita' non valida! Possibile attacco Man-in-the-Middle."
                msg.pop('json', None)
                msg['is_json'] = False
                return
        else:
            if ikey and ikey != saved_ikey:
                msg['error'] = "Tentativo di alterare la chiave di identita' storica."
                msg.pop('json', None)
                msg['is_json'] = False
                return

        key_to_save = saved_ikey 

    store_public_key_in_vault(
        data,
        chat_id,
        sender_id,
        public,
        kid=kid,
        kid_cif=kid_cif,
        pub_sign=pub_sign,
        chat_group=group_chat,
        group_title=getattr(entity, 'title', 'Gruppo'),
        ikey=key_to_save 
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

    chats_data = data.get('data', {}).get('chats', {})
    chat_keys = chats_data.get(chat_id_cif, {})
    private = build_candidate_privates(chat_keys, kids)

    decrypted_text = decrypt_with_age(text, private)
    if not decrypted_text:
        msg['error'] = "impossibile decifrare il messaggio"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    try:
        dic_mes = json.loads(decrypted_text)
        sign_, sign_error = verify_sig_cb(msg.get('sender_id'), msg_decrypted_id_caption, kid, kid_cif, seq, "on", sign, kids, dic_mes.get('text'))
        if not sign_:
            msg['error'] = sign_error
            msg.pop('json', None)
            msg['is_json'] = False
            return

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
    msg['metadata_plain'], _ = await take_file_data(client, entity, msg, "file")

    if not msg.get('metadata_plain'):
        msg['error'] = "Il download dei metadati non è andato a buon fine"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    metadata_plain = msg['metadata_plain']
    msg_id = metadata_plain.get('id')
    seq = metadata_plain.get('seq')
    kid = metadata_plain.get('kid')
    kid_cif = metadata_plain.get('kid_cif')
    sign = metadata_plain.get('sign')
    kids = metadata_plain.get('kids')
    
    encrypted_inner_metadata = metadata_plain.get('text')

    if any(t is None for t in (seq, kid, kid_cif, sign, msg_id, kids, encrypted_inner_metadata)):
        msg['error'] = "metadati mancanti o incompleti"
        msg.pop('json', None)
        msg['is_json'] = False
        return

    chats_data = data.get('data', {}).get('chats', {})
    chat_keys = chats_data.get(chat_id_cif, {})
    private = build_candidate_privates(chat_keys, kids)

    decrypted_text = decrypt_with_age(encrypted_inner_metadata, private)
    if not decrypted_text:
        msg['error'] = "impossibile decifrare i metadati"
        msg.pop('json', None)
        msg['is_json'] = False
        return
    
    try:
        dic_mes = json.loads(decrypted_text)

        if (dic_mes.get('cif') != "file" or 
            dic_mes.get('id') != msg_id or 
            dic_mes.get('seq') != seq or 
            dic_mes.get('kid') != kid or 
            dic_mes.get('sign') != sign):
            
            msg['error'] = "questo messaggio e' stato modificato (incongruenza nei metadati)"
            msg.pop('json', None)
            msg['is_json'] = False
            return


        sign_, sign_error = verify_sig_cb(msg.get('sender_id'), msg_id, kid, kid_cif, seq, "file", sign, kids, dic_mes.get('text'))
        if not sign_:
            msg['error'] = sign_error
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
        msg['filename'] = dic_mes.get('filename')
        msg['text'] = dic_mes.get('text')  
        msg['mime'] = dic_mes.get('mime')
        msg['size'] = dic_mes.get('size')
        
        msg['secure'] = True
        msg['_secure_seq'] = seq
        msg['_secure_sender_key'] = str(msg.get('sender_id')) if msg.get('sender_id') is not None else "unknown"

        msg.pop('encrypted_metadata', None)
        msg.pop('metadata_plain', None)
        msg.pop('json', None)
        msg['is_json'] = False

    except Exception:
        msg['error'] = "errore nella lettura dei metadati del file"
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

    chats_data = data.get('data', {}).get('chats', {})
    chat_keys = chats_data.get(chat_id_cif, {})
    private = build_candidate_privates(chat_keys, kids)

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

            sign_, sign_error = verify_sig_cb(msg.get('sender_id'), msg_decrypted_id_caption, kid, kid_cif, seq, "message", sign, kids, message_bytes.decode('utf-8', errors='replace'))
            if not sign_:
                msg['error'] = sign_error
                msg.pop('json', None)
                msg['is_json'] = False
                return

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
