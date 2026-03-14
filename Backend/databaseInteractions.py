from database.sqlite import get_connection, db_lock
from fastapi import HTTPException
import sqlite3
from cryptography_ import deriva_master_key, decifra_vault, cifra_vault
import hashlib
from config import pepper

#questa funzione prende i dati dell'utente (vault e salt) e li decifra prendendo in input lo 
#username dell'utente passato in una funzione di hash e la sua password(in versione passphrase)
def get_user_informations(username: str, password: str):
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)
            cursor.execute(
                "SELECT salt, vault FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati is None:
                raise HTTPException(status_code=401)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    salt_db = risultati[0]
    
    salt_bytes = salt_db

    master_key = deriva_master_key(password, salt_bytes)

    try:
        vault_decyphered = decifra_vault(risultati[1], master_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return vault_decyphered, master_key

#la funzione che si occupa di modificare il vault di un utente dato in input
def set_user_vault(username: str, vault_cyphered: bytes):
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE utenti SET vault = ? WHERE username = ?",
                (vault_cyphered, username),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

def add_user(temp_data, vault_cyphered):
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO utenti (username, salt, vault) VALUES (?, ?, ?)",
                (temp_data['username'], temp_data['salt'], vault_cyphered),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
#verifica l'unicita' dello username
def check_username_unicity(username: str):
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)  
            cursor.execute(
                "SELECT * FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati != None:
                raise HTTPException(status_code=400)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

#prende il vault dei partecipanti al gruppo
def get_gruppo_vault(username: str, chat_id: str, entity, data):
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    with db_lock, get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
            (username, chat_id_cif)
        )
        risultato = cursor.fetchone()
        if not risultato or not risultato[0]:
            vault_deciphered = {
                'gruppo_id': chat_id,
                'gruppo_nome': getattr(entity, 'title', 'Gruppo'),
                'partecipanti': {}
            }
            insert_new_vault = True
        else:
            vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
            insert_new_vault = False
    return insert_new_vault, vault_deciphered
                
#prende il vault di una chat
async def get_chat_vault(username: str, chat_id: str, client, data):
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    with db_lock, get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
            (username, chat_id_cif)
        )
        risultato = cursor.fetchone()
        if not risultato or not risultato[0]:
            sender = await client.get_entity(chat_id)
            vault_deciphered = {
                'user_id': chat_id,
                'username': getattr(sender, 'username', str(chat_id)) if sender else str(chat_id),
                'chiavi_cif': {},
                'chiavi_firma': {},
            }
            insert_new_vault = True
        else:
            vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
            insert_new_vault = False
    return insert_new_vault, vault_deciphered

def store_public_key_in_vault(
    user_data,
    chat_id: int,
    sender_id,
    public_key: str,
    kid: str | None = None,
    kid_cif: str | None = None,
    pub_sign: str | None = None,
    msg_date=None,
    is_group: bool | None = None,
    group_title: str | None = None,
    sender_username: str | None = None,
):
    if not user_data or not public_key:
        return False

    if is_group is None:
        try:
            is_group = int(chat_id) < 0
        except Exception:
            is_group = False

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
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    vault_deciphered = {
                        'gruppo_id': chat_id,
                        'gruppo_nome': group_title or 'Gruppo',
                        'partecipanti': {}
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
            else:
                cursor.execute(
                    """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    vault_deciphered = {
                        'user_id': chat_id,
                        'username': sender_username or str(chat_id),
                        'chiavi_cif': {},
                        'chiavi_firma': {},
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
    except sqlite3.Error:
        return False

    vault_dirty = False

    if is_group:
        partecipanti = vault_deciphered.setdefault('partecipanti', {})
        if not isinstance(partecipanti, dict):
            partecipanti = {}
            vault_deciphered['partecipanti'] = partecipanti

        sender_id_str = str(sender_id) if sender_id is not None else ''
        participant_data = partecipanti.get(sender_id_str)
        if participant_data is None:
            participant_data = partecipanti.get(sender_id)
        if not isinstance(participant_data, dict):
            participant_data = {}

        if not isinstance(participant_data.get('chiavi_cif'), dict):
            participant_data['chiavi_cif'] = {}
            vault_dirty = True

        if not isinstance(participant_data.get('chiavi_firma'), dict):
            participant_data['chiavi_firma'] = {}
            vault_dirty = True

        partecipanti[sender_id_str] = participant_data
    else:
        if not isinstance(vault_deciphered.get('chiavi_cif'), dict):
            vault_deciphered['chiavi_cif'] = {}
            vault_dirty = True

        if not isinstance(vault_deciphered.get('chiavi_firma'), dict):
            vault_deciphered['chiavi_firma'] = {}
            vault_dirty = True

    # Salva la chiave pubblica di firma per kid quando disponibile.
    if isinstance(kid, str) and kid and isinstance(pub_sign, str) and pub_sign:
        if is_group:
            sender_id_str = str(sender_id) if sender_id is not None else ''
            partecipanti = vault_deciphered.setdefault('partecipanti', {})
            if sender_id_str not in partecipanti:
                partecipanti[sender_id_str] = {'chiavi_cif': {}, 'chiavi_firma': {}}

            participant_data = partecipanti[sender_id_str]
            signing_keys = participant_data.get('chiavi_firma', {})
            if not isinstance(signing_keys, dict):
                signing_keys = {}

            if signing_keys.get(kid) != pub_sign:
                signing_keys[kid] = pub_sign
                participant_data['chiavi_firma'] = signing_keys
                vault_dirty = True
        else:
            signing_keys = vault_deciphered.get('chiavi_firma', {})
            if not isinstance(signing_keys, dict):
                signing_keys = {}

            if signing_keys.get(kid) != pub_sign:
                signing_keys[kid] = pub_sign
                vault_deciphered['chiavi_firma'] = signing_keys
                vault_dirty = True

    added_age_key = False

    resolved_kid_cif = kid_cif if isinstance(kid_cif, str) and kid_cif else hashlib.sha256(public_key.encode()).hexdigest()[:16]
    if is_group:
        sender_id_str = str(sender_id) if sender_id is not None else ''
        partecipanti = vault_deciphered.setdefault('partecipanti', {})
        if sender_id_str not in partecipanti:
            partecipanti[sender_id_str] = {'chiavi_cif': {}, 'chiavi_firma': {}}

        participant_data = partecipanti[sender_id_str]
        cif_keys = participant_data.get('chiavi_cif', {})
        if not isinstance(cif_keys, dict):
            cif_keys = {}
        existing = cif_keys.get(resolved_kid_cif)
        if not isinstance(existing, dict) or existing.get('chiave') != public_key:
            cif_keys[resolved_kid_cif] = {'chiave': public_key}
            participant_data['chiavi_cif'] = cif_keys
            vault_dirty = True
            added_age_key = True
    else:
        cif_keys = vault_deciphered.get('chiavi_cif', {})
        if not isinstance(cif_keys, dict):
            cif_keys = {}
        existing = cif_keys.get(resolved_kid_cif)
        if not isinstance(existing, dict) or existing.get('chiave') != public_key:
            cif_keys[resolved_kid_cif] = {'chiave': public_key}
            vault_deciphered['chiavi_cif'] = cif_keys
            vault_dirty = True
            added_age_key = True

    if not vault_dirty:
        return False

    vault_cifrato = cifra_vault(vault_deciphered, user_data['data']['masterkey'])
    try:
        with db_lock, get_connection() as conn:
            cursor = conn.cursor()
            if is_group:
                if insert_new_vault:
                    cursor.execute(
                        """INSERT INTO contatti_gruppo (proprietario, gruppo_id, vault) VALUES (?, ?, ?)""",
                        (username, chat_id_cif, vault_cifrato)
                    )
                else:
                    cursor.execute(
                        """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                        (vault_cifrato, username, chat_id_cif)
                    )
            else:
                if insert_new_vault:
                    cursor.execute(
                        """INSERT INTO contatti (proprietario, contatto_id, vault) VALUES (?, ?, ?)""",
                        (username, chat_id_cif, vault_cifrato)
                    )
                else:
                    cursor.execute(
                        """UPDATE contatti SET vault = ? WHERE proprietario = ? AND contatto_id = ?""",
                        (vault_cifrato, username, chat_id_cif)
                    )
            conn.commit()
    except sqlite3.Error:
        return False

    return added_age_key or vault_dirty

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

    recipient_keys = []
    if risultato and risultato[0]:
        vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
        if 'partecipanti' in vault_deciphered and isinstance(vault_deciphered['partecipanti'], dict):
            for participant_data in vault_deciphered['partecipanti'].values():
                if not isinstance(participant_data, dict):
                    continue
                cif_map = participant_data.get('chiavi_cif', {})
                if isinstance(cif_map, dict):
                    for key_data in cif_map.values():
                        if isinstance(key_data, dict) and key_data.get('chiave'):
                            recipient_keys.append(key_data['chiave'])

    if 'chats' in data['data'] and chat_id in data['data']['chats']:
        chat_data = data['data']['chats'][chat_id]
        user_pubblica = None
        age_key_map = chat_data.get('chiavi_cif', {})
        current_kid_cif = chat_data.get('kid_cif_corrente')
        if isinstance(age_key_map, dict) and isinstance(current_kid_cif, str):
            selected = age_key_map.get(current_kid_cif)
            if isinstance(selected, dict):
                user_pubblica = selected.get('pubblica')

        if user_pubblica and user_pubblica not in recipient_keys:
            recipient_keys.append(user_pubblica)
                
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
            risultato = cursor.fetchone()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    recipient_keys = []
    if risultato and risultato[0]:
        vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
        cif_map = vault_deciphered.get('chiavi_cif', {})
        if isinstance(cif_map, dict):
            for key_data in cif_map.values():
                if isinstance(key_data, dict) and key_data.get('chiave'):
                    recipient_keys.append(key_data['chiave'])

    if 'chats' in data['data'] and chat_id in data['data']['chats']:
        chat_data = data['data']['chats'][chat_id]
        user_pubblica = None
        age_key_map = chat_data.get('chiavi_cif', {})
        current_kid_cif = chat_data.get('kid_cif_corrente')
        if isinstance(age_key_map, dict) and isinstance(current_kid_cif, str):
            selected = age_key_map.get(current_kid_cif)
            if isinstance(selected, dict):
                user_pubblica = selected.get('pubblica')

        if user_pubblica and user_pubblica not in recipient_keys:
            recipient_keys.append(user_pubblica)
    
    if not recipient_keys:
        raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")

    else:
        return recipient_keys
