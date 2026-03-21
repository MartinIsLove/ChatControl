from database.sqlite import get_connection, db_lock
from fastapi import HTTPException
import sqlite3, hashlib
from utils import is_group_chat_id
from cryptography_ import derivate_master_key, decrypt_vault, encrypt_vault
from config import pepper

def get_user_informations(username: str, password: str):
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)
            cursor.execute(
                "SELECT salt, vault FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            results = cursor.fetchone()
            if results is None:
                raise HTTPException(status_code=401)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    salt_db = results[0]
    
    salt_bytes = salt_db

    master_key = derivate_master_key(password, salt_bytes)

    try:
        vault_decyphered = decrypt_vault(results[1], master_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return vault_decyphered, master_key

def set_user_vault(username: str, vault_ciphered: bytes):
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE utenti SET vault = ? WHERE username = ?",
                (vault_ciphered, username),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

def add_user(temp_data, vault_ciphered):
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO utenti (username, salt, vault) VALUES (?, ?, ?)",
                (temp_data['username'], temp_data['salt'], vault_ciphered),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

def check_username_unicity(username: str):
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)  
            cursor.execute(
                "SELECT * FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            results = cursor.fetchone()
            if results != None:
                raise HTTPException(status_code=400)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

def get_gruppo_vault(username: str, chat_id: str, entity, data):
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    with db_lock, get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
            (username, chat_id_cif)
        )
        result = cursor.fetchone()
        if not result or not result[0]:
            vault_deciphered = {
                'gruppo_id': chat_id,
                'gruppo_nome': getattr(entity, 'title', 'Gruppo'),
                'partecipanti': {}
            }
            insert_new_vault = True
        else:
            vault_deciphered = decrypt_vault(result[0], data['data']['masterkey'])
            insert_new_vault = False
    return insert_new_vault, vault_deciphered
                
async def get_chat_vault(username: str, chat_id: str, client, data):
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    with db_lock, get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
            (username, chat_id_cif)
        )
        result = cursor.fetchone()
        if not result or not result[0]:
            sender = await client.get_entity(chat_id)
            vault_deciphered = {
                'user_id': chat_id,
                'username': getattr(sender, 'username', str(chat_id)) if sender else str(chat_id),
                'chiavi_cif': {},
                'chiavi_firma': {},
            }
            insert_new_vault = True
        else:
            vault_deciphered = decrypt_vault(result[0], data['data']['masterkey'])
            insert_new_vault = False
    return insert_new_vault, vault_deciphered

def store_public_key_in_vault(
    user_data: dict,
    chat_id: int,
    sender_id: int,
    public_key: str,
    kid: str | None = None,
    kid_cif: str | None = None,
    pub_sign: str | None = None,
    is_group: bool | None = None,
    group_title: str | None = None,
    sender_username: str | None = None,
):
    if str(user_data['data'].get('user_id')) == str(sender_id):
        return False

    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    vault_deciphered = None
    insert_new_vault = False

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
                    vault_deciphered = {
                        'gruppo_id': chat_id,
                        'gruppo_nome': group_title or 'Gruppo',
                        'partecipanti': {}
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decrypt_vault(result[0], user_data['data']['masterkey'])
            else:
                cursor.execute(
                    """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                result = cursor.fetchone()
                if not result or not result[0]:
                    vault_deciphered = {
                        'user_id': chat_id,
                        'username': sender_username or str(chat_id),
                        'chiavi_cif': {},
                        'chiavi_firma': {},
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decrypt_vault(result[0], user_data['data']['masterkey'])
    except sqlite3.Error:
        return False

    if is_group:
        participants = vault_deciphered.setdefault('partecipanti', {})
        

        sender_id_str = str(sender_id)
        participant_data = participants.get(sender_id_str)
        if participant_data is None:
            participant_data = participants.get(sender_id)

        participants.setdefault(sender_id_str, {})

        participant_data= participants.get(sender_id_str)

        participant_data.setdefault('chiavi_cif',{})
        
        if kid_cif not in participant_data['chiavi_cif']:
            participant_data['chiavi_cif'][kid_cif] = public_key

        participant_data.setdefault('kid_cif_corrente',{})
    
        participant_data['kid_cif_corrente']= kid_cif

        participant_data.setdefault('chiavi_firma',{})
        
        if kid not in participant_data['chiavi_firma']:
            participant_data['chiavi_firma'][kid]= pub_sign

        participant_data.setdefault('kid_corrente',{})
        
        participant_data['kid_corrente']= kid

        participants[sender_id_str] = participant_data
    else:
        participant_data = vault_deciphered

        participant_data.setdefault('chiavi_cif',{})
        
        if kid_cif not in participant_data['chiavi_cif']:
            participant_data['chiavi_cif'][kid_cif] = public_key    

        participant_data.setdefault('kid_cif_corrente',{})
        participant_data['kid_cif_corrente']= kid_cif

        participant_data.setdefault('chiavi_firma',{})
        
        if kid not in participant_data['chiavi_firma']:
            participant_data['chiavi_firma'][kid]= pub_sign

        participant_data.setdefault('kid_corrente',{})
        
        participant_data['kid_corrente']= kid

        

    
    chats_vault_update(vault_deciphered, user_data, username, chat_id, insert_new_vault)
    

    return True

def chats_vault_update(vault, user_data, username, chat_id, insert_new_vault):
    vault_ciphered = encrypt_vault(vault, user_data['data']['masterkey'])
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            if is_group_chat_id(chat_id):
                if insert_new_vault:
                    cursor.execute(
                        """INSERT INTO contatti_gruppo (proprietario, gruppo_id, vault) VALUES (?, ?, ?)""",
                        (username, chat_id_cif, vault_ciphered)
                    )
                else:
                    cursor.execute(
                        """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                        (vault_ciphered, username, chat_id_cif)
                    )
            else:
                if insert_new_vault:
                    cursor.execute(
                        """INSERT INTO contatti (proprietario, contatto_id, vault) VALUES (?, ?, ?)""",
                        (username, chat_id_cif, vault_ciphered)
                    )
                else:
                    cursor.execute(
                        """UPDATE contatti SET vault = ? WHERE proprietario = ? AND contatto_id = ?""",
                        (vault_ciphered, username, chat_id_cif)
                    )
            conn.commit()
    except sqlite3.Error:
        return False

def get_group_chyper_keys(data, chat_id1):
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()
    
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                (username, chat_id)
            )
            risultato = cursor.fetchone()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    recipient_keys = {}
    if risultato and risultato[0]:
        vault_deciphered = decrypt_vault(risultato[0], data['data']['masterkey'])
        if 'partecipanti' in vault_deciphered:
            for participant_data in vault_deciphered['partecipanti'].values():
                current_kid_cif = participant_data.get('kid_cif_corrente')
                cif_map = participant_data.get('chiavi_cif', {}).get(current_kid_cif)                
                recipient_keys[current_kid_cif] = cif_map

    if 'chats' in data['data'] and chat_id in data['data']['chats']:
        chat_data = data['data']['chats'][chat_id]
        user_public = None
        age_key_map = chat_data.get('chiavi_cif', {})
        current_kid_cif = chat_data.get('kid_cif_corrente')
        
        selected = age_key_map.get(current_kid_cif)
        
        user_public = selected.get('pubblica')

        if user_public and user_public not in recipient_keys:
            recipient_keys[current_kid_cif] = user_public
                
    if not recipient_keys:
        raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")
    else:
        return recipient_keys
    
def get_chat_chyper_keys(data, chat_id1):
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()

    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                (username, chat_id)
            )
            result = cursor.fetchone()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    recipient_keys = {}
    if result and result[0]:
        vault_deciphered = decrypt_vault(result[0], data['data']['masterkey'])
        cif_map = vault_deciphered.get('chiavi_cif', {})
        current_kid_cif = vault_deciphered.get('kid_cif_corrente')
        cif_map = vault_deciphered.get('chiavi_cif', {}).get(current_kid_cif)                
        recipient_keys[current_kid_cif] = cif_map 

    if 'chats' in data['data'] and chat_id in data['data']['chats']:
        chat_data = data['data']['chats'][chat_id]
        user_public = None
        age_key_map = chat_data.get('chiavi_cif', {})
        current_kid_cif = chat_data.get('kid_cif_corrente')
        
        selected = age_key_map.get(current_kid_cif)
        
        user_public = selected.get('pubblica')

        if user_public and user_public not in recipient_keys:
            recipient_keys[current_kid_cif] = user_public
    
    if not recipient_keys:
        raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")

    else:
        return recipient_keys
