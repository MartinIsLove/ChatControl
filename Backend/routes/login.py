from fastapi import APIRouter, Response, Cookie, HTTPException
from pydantic import BaseModel
import secrets, time, hashlib
from config import pepper
from cryptography_ import encrypt_vault
from utils import cipher, login_cache, is_logged_in
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError
from databaseInteractions import get_user_informations, set_user_vault

router = APIRouter()

class login_user(BaseModel):
    username: str
    password: str

class code(BaseModel):
    sms: str
    password: str

#la funzione che si occupa di loggare l'utente
@router.post("/login")
async def login_user(credentials: login_user, response: Response):


    
    #calcolo l'hash dello username per poter cercare le sue informazioni nel database
    username = hashlib.sha256(pepper.encode() + credentials.username.encode()).hexdigest()
    #calcolo il suo id temporaneo che serve poi per settare il coockie dell'utente e il suo campo in RAM
    temp_id = secrets.token_hex(16)
    #lo cifro
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    
    vault_decyphered, masterkey= get_user_informations(username, credentials.password)
    
    # Inizializza il campo chats se non esiste
    if 'chats' not in vault_decyphered:
        vault_decyphered['chats'] = {}
    
    #recupera la sessione
    client = TelegramClient(StringSession(vault_decyphered['session']), vault_decyphered['api_id'], vault_decyphered['api_hash'])
    vault_decyphered['masterkey'] =  masterkey
    global login_cache
    login_cache[temp_id] = {
        "data": vault_decyphered,
        "time": time.time(),
        "client": client
    }

    response.set_cookie(
        key="login_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="strict",
    )

    await client.connect()

    if not await client.is_user_authorized():
        try:
            await client.disconnect()
            client = TelegramClient(StringSession(), vault_decyphered['api_id'], vault_decyphered['api_hash'])
            await client.connect()

            sent_code = await client.send_code_request(vault_decyphered['phone'])
            login_cache[temp_id] = {
                "data": vault_decyphered,
                "time": time.time(),
                "client": client,
                "sent_code": sent_code
            }
            return {"status":"session expired"}
        except Exception as e:
            await client.disconnect()
            raise HTTPException(status_code=500, detail=f"Errore invio SMS: {str(e)}")

    return {"status":"logged in"}

#funzione che viene chiamata quando la sessione era scaduta, si occupa dell'inserimento del SMS
@router.post("/login/expired")
async def login_user_expired(credentials: code, login_session: str = Cookie(None)):
    
    if not login_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(login_session.encode()).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Sessione invalida")
    
    global login_cache

    temp_data = login_cache.get(temp_id)
    client = temp_data['client']
    #invio a telegram dell'SMS per il login
    try: 
        await client.sign_in(temp_data['data']['phone'], credentials.sms, phone_code_hash = temp_data['sent_code'].phone_code_hash)
        session = client.session.save()
    #se l'SMS viene accettato ma nell'account e' richiesta la verifica a piu' fattori
    #prendo la password dai dati temporanei in RAM
    except SessionPasswordNeededError:
        try:
            await client.sign_in(password = credentials.password)
            session = client.session.save()
        except Exception as e:
            raise HTTPException(status_code=401, detail=str(e))
    temp_data['data']['session'] = session
    if 'masterkey' in temp_data['data']:
        data = temp_data['data'].copy()
        del data['masterkey']
        vault_ciphered = encrypt_vault(data, temp_data['data']['masterkey'])

    else:
        vault_ciphered = encrypt_vault(temp_data['data'], temp_data['data']['masterkey'])
    
    username = hashlib.sha256(pepper.encode() + temp_data['data']['username'].encode()).hexdigest()
    
    set_user_vault(username, vault_ciphered)
    
    return {"status":"logged in"}

#funzione che si occupa della verifica del login
@router.get("/login/check")
async def login_check(login_session: str = Cookie(None)):
    is_logged_in(login_session)
    return {"status": "ok"}

#funzione che si occupa di fare il logout
@router.post("/logout")
async def logout(response: Response, login_session: str = Cookie(None)):
    if login_session:
        try:
            temp_id = cipher.decrypt(login_session.encode()).decode()
            temp_data = login_cache.pop(temp_id, None)
            client = temp_data.get("client") if temp_data else None
            if client:
                try:
                    await client.disconnect()
                except Exception:
                    raise HTTPException(status_code=500)

        except Exception:
            raise HTTPException(status_code=500)


    response.delete_cookie(
        key="login_session",
        httponly=True,
        secure=True,
        samesite="strict",
    )
    return {"status": "logged out"}