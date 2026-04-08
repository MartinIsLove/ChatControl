import subprocess, base64, json, os, hashlib, tempfile, asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from utils import is_group
from config import pepper

def derive_signing_keys_from_age_private(age_private_key: str):
    
    normalized = age_private_key.strip()
    if not normalized:
        raise ValueError("Chiave privata age mancante")
    if not normalized.startswith("AGE-SECRET-KEY-1"):
        raise ValueError("Formato chiave privata age non valido")

    seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"chatcontrol-age-signing-salt-v1",
        info=b"chatcontrol-age-signing-derivation-v1",
    ).derive(normalized.encode("ascii"))

    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    kid_full = hashes.Hash(hashes.SHA256())
    kid_full.update(public_bytes)
    kid = kid_full.finalize()[:16]

    return {
        "private_key": base64.urlsafe_b64encode(private_bytes).decode(),
        "public_key": base64.urlsafe_b64encode(public_bytes).decode(),
        "kid": base64.urlsafe_b64encode(kid).decode(),
    }

def calculate_message_sign(private_key_b64url: str, seq = None, kid = None, kid_cif = None, message_id = None, cif = None, kids = None, text = None, file = None, file_hash: bytes = None, identity = None):
   
    try:
        private_key_raw = base64.urlsafe_b64decode(private_key_b64url.strip())
    except Exception as exc:
        raise ValueError("Formato chiave privata di firma non valido") from exc

    if len(private_key_raw) != 32:
        raise ValueError("La chiave privata di firma deve essere lunga 32 byte")
    if identity:
        payload = {
                "seq": seq,
                "kid": kid.strip(),
                "kid_cif": kid_cif.strip(),
                "id": message_id.strip(),
        }
    else:
        if file_hash is not None:
            payload = {"file_hash": base64.urlsafe_b64encode(file_hash).decode()}
        elif file is not None:
            payload = {"file": base64.urlsafe_b64encode(file).decode()}
        else:
            sanitized_kids = [str(k).strip() for k in kids] if kids else[]

            payload = {
                "seq": seq,
                "kid": kid.strip(),
                "kid_cif": kid_cif.strip(),
                "id": message_id.strip(),
                "cif": cif.strip(),
                "kids": sanitized_kids,
                "text": text
            }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    signer = Ed25519PrivateKey.from_private_bytes(private_key_raw)
    signature = signer.sign(payload_bytes)
    return base64.urlsafe_b64encode(signature).decode()

def verify_message_sign(public_key_b64url: str, signature_b64url: str, seq = None, kid = None, kid_cif = None, message_id = None, cif = None, kids = None, text = None, file = None, file_hash: bytes = None, identity = None
):
   
    try:
        public_key_raw = base64.urlsafe_b64decode(public_key_b64url.strip())
    except Exception as exc:
        raise ValueError("Formato chiave pubblica di firma non valido") from exc

    if len(public_key_raw) != 32:
        raise ValueError("La chiave pubblica di firma deve essere lunga 32 byte")

    try:
        signature_raw = base64.urlsafe_b64decode(signature_b64url.strip())
    except Exception:
        return False

    if identity:
        payload = {
                "seq": seq,
                "kid": kid.strip(),
                "kid_cif": kid_cif.strip(),
                "id": message_id.strip(),
        }

    elif file_hash is not None:
        payload = {"file_hash": base64.urlsafe_b64encode(file_hash).decode()}
    elif file:
        payload = { "file": base64.urlsafe_b64encode(file).decode()}
    else:
        sanitized_kids = [str(k).strip() for k in kids] if kids else[]
        payload = {
            "seq": seq,
            "kid": kid.strip(),
            "kid_cif": kid_cif.strip(),
            "id": message_id.strip(),
            "cif": cif.strip(),
            "kids": sanitized_kids,
            "text": text
        }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    verifier = Ed25519PublicKey.from_public_bytes(public_key_raw)
    try:
        verifier.verify(signature_raw, payload_bytes)
        return True
    except InvalidSignature:
        return False

def derive_master_key(passphrase: str, salt: bytes):
    kdf = Argon2id(salt=salt, length=32, iterations=2, memory_cost=65536, lanes=4)
    raw_key = kdf.derive(passphrase.encode())
    master_key_base64 = base64.urlsafe_b64encode(raw_key)
    return master_key_base64

def key_sign_gen():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    kid_full = hashes.Hash(hashes.SHA256())
    kid_full.update(public_bytes)
    kid = kid_full.finalize()[:16]

    return  base64.urlsafe_b64encode(private_bytes).decode(), base64.urlsafe_b64encode(public_bytes).decode(),  base64.urlsafe_b64encode(kid).decode()
    
def encrypt_vault(dic_mess, master_key):
    try:
        json_data = json.dumps(dic_mess)
        f = Fernet(master_key)
        encr_blob = f.encrypt(json_data.encode())
        return encr_blob
    except Exception as e:
        raise ValueError("Errore nella cifratura del vault") from e

def decrypt_vault(encr_blob, master_key):
    try:
        f = Fernet(master_key)
        json_data = f.decrypt(encr_blob).decode()
        return json.loads(json_data)
    except Exception as e:
        raise ValueError("Errore nella decifrazione del vault") from e

def encrypt_with_age(plaintext: str | bytes, public_keys: list):
    
    try:
        args = ['age']
        for key in public_keys:
            args.extend(['-r', key])
        
        if isinstance(plaintext, bytes):
            input_data = plaintext
        else:
            input_data = plaintext.encode()
        
        result = subprocess.run(args, input=input_data, capture_output=True, check=True)
        ciphertext = result.stdout
        
        return base64.b64encode(ciphertext).decode()
    except subprocess.CalledProcessError:
        return None
    
def decrypt_with_age(text, private, decode=True):
    key_read_fd = None
    keyfile_path = None
    try:
        try:
            text_bytes = base64.b64decode(text)
        except:
            text_bytes = text if isinstance(text, (bytes, bytearray)) else str(text).encode()

        if os.name == 'nt':
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.age') as encfile:
                encfile.write(text_bytes)
                encfile_path = encfile.name

            try:
                result = subprocess.run(
                    ['age', '-d', '-i', '-', encfile_path],
                    input=private.strip().encode('ascii') + b'\n',
                    capture_output=True,
                    check=True
                )
            finally:
                if os.path.exists(encfile_path):
                    os.unlink(encfile_path)

        else:
            key_read_fd, key_write_fd = os.pipe()
            os.set_inheritable(key_read_fd, True)

            with os.fdopen(key_write_fd, 'wb') as key_pipe:
                key_pipe.write(private.strip().encode('ascii') + b'\n')

            result = subprocess.run(
                ['age', '-d', '-i', f'/proc/self/fd/{key_read_fd}'],
                input=text_bytes,
                capture_output=True,
                check=True,
                pass_fds=(key_read_fd,)
            )
        
        if decode:
            decrypted_text = result.stdout.decode()
        else:
            decrypted_text = result.stdout
            
    except Exception:
        return None
    finally:
        if key_read_fd is not None:
            try:
                os.close(key_read_fd)
            except OSError:
                pass
        if keyfile_path and os.path.exists(keyfile_path):
            os.unlink(keyfile_path)
                
    return decrypted_text

async def feed_encrypted_to_age_process(proc, encrypted_path: str, encrypted_data_offset: int, chunk_size: int):
    try:
        with open(encrypted_path, 'rb') as encrypted_in:
            encrypted_in.seek(encrypted_data_offset)
            while True:
                chunk = encrypted_in.read(chunk_size)
                if not chunk:
                    break
                proc.stdin.write(chunk)
                await proc.stdin.drain()
        proc.stdin.close()
    except Exception:
        proc.stdin.close()

async def decrypt_file_with_age_stream(encrypted_path: str, decrypted_path: str, private_age_key: str, encrypted_data_offset: int = 0, chunk_size: int = 65536,
) -> bytes:
    file_hash = hashlib.sha256()
    key_read_fd = None
    key_write_fd = None
    key_path = None
    key_task = None
    try:
        if os.name == 'nt':
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
                key_file.write(private_age_key)
                key_path = key_file.name

            proc = await asyncio.create_subprocess_exec(
                'age', '-d', '-i', key_path,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            key_read_fd, key_write_fd = os.pipe()
            os.set_inheritable(key_read_fd, True)

            proc = await asyncio.create_subprocess_exec(
                'age', '-d', '-i', f'/proc/self/fd/{key_read_fd}',
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(key_read_fd,),
            )

            os.close(key_read_fd)
            key_read_fd = None

            async def feed_key_to_age_process(fd: int, key: str):
                key_bytes = key.strip().encode('ascii') + b'\n'
                with os.fdopen(fd, 'wb', closefd=True) as key_pipe:
                    key_pipe.write(key_bytes)
                    key_pipe.flush()

            key_task = asyncio.create_task(feed_key_to_age_process(key_write_fd, private_age_key))
            key_write_fd = None

        input_task = asyncio.create_task(
            feed_encrypted_to_age_process(proc, encrypted_path, encrypted_data_offset, chunk_size)
        )

        with open(decrypted_path, 'wb') as out_f:
            while True:
                chunk = await proc.stdout.read(chunk_size)
                if not chunk:
                    break
                file_hash.update(chunk)
                out_f.write(chunk)

        if key_task is not None:
            await key_task
        await input_task
        await proc.wait()

        if proc.returncode != 0:
            err = await proc.stderr.read()
            raise RuntimeError(f"Decifratura file fallita: {err.decode().strip()}")

        return file_hash.digest()
    finally:
        if key_read_fd is not None:
            os.close(key_read_fd)
        if key_write_fd is not None:
            os.close(key_write_fd)
        if key_path and os.path.exists(key_path):
            try:
                with open(key_path, 'wb') as wipe_file:
                    wipe_file.write(b'\0' * 100)
            except Exception:
                pass
            os.remove(key_path)

def encrypt_file_with_age(src_path: str, dest_path: str, public_keys: list):
    try:
        args = ['age']
        for key in public_keys:
            args.extend(['-r', key])
        
        with open(src_path, 'rb') as f_in, open(dest_path, 'wb') as f_out:
            subprocess.run(args, stdin=f_in, stdout=f_out, check=True)
        return True
    except Exception:
        return False

def get_file_sha256(file_path: str):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.digest()

def key_gen_age():
    try:
        risultato = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True)
        output = risultato.stdout
        linee = output.splitlines()
        public = ""
        private = ""
        for linea in linee:
            if linea.startswith("# public key:"):
                public = linea.split(":")[1].strip()
            elif linea.startswith("AGE-SECRET-KEY-1"):
                private = linea.strip()
        if public and private:
            return public, private
        else:
            return None, None
    except subprocess.CalledProcessError:
        return None, None
    
def verify_signed_payload(data, chat_id, my_id, sender_id, payload_id, payload_kid, payload_kid_cif, payload_seq, payload_cif, payload_sign, kids, text=None, file=None, file_hash: bytes = None, chat_vault=None):
    
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    
    if my_id and sender_id == my_id:
        local_kid_map = data.get('data', {}).get('chats', {}).get(chat_id_cif, {}).get('kid', {})
        sign_private = local_kid_map.get(payload_kid) if isinstance(local_kid_map, dict) else None
        if not sign_private:
            return False, "chiave di firma locale non disponibile"
        try:
            if file_hash is not None:
                expected_sign = calculate_message_sign(sign_private, file_hash=file_hash)
                if not expected_sign:
                    return False, "firma file non verificabile"
            elif file is not None:
                expected_sign = calculate_message_sign(sign_private, file=file)
            else:
                expected_sign = calculate_message_sign(sign_private, payload_seq, payload_kid, payload_kid_cif, payload_id, payload_cif, kids, text)
        except ValueError:
            return False, "questo messaggio e' stato modificato"
        if file_hash is not None:
            return (payload_sign == expected_sign), "firma file non valida"
        return (payload_sign == expected_sign), "questo messaggio e' stato modificato"

    signing_keys = {}
    
    if chat_vault:
        if is_group(chat_id):
            participant_data = chat_vault.get('partecipanti', {}).get(str(sender_id))
            if participant_data is None:
                participant_data = chat_vault.get('partecipanti', {}).get(sender_id, {})
            signing_keys = participant_data.get('chiavi_firma', {})
        else:
            signing_keys = chat_vault.get('chiavi_firma', {}) 
    else:
        from realtime import get_remote_signing_keys
        signing_keys = get_remote_signing_keys(data, chat_id, sender_id)

    pub_sign = signing_keys.get(payload_kid) if isinstance(signing_keys, dict) else None
    
    if not pub_sign:
        return False, "chiave di firma mittente non disponibile"

    try:
        if file_hash is not None:
            is_valid = verify_message_sign(pub_sign, payload_sign, file_hash=file_hash)
            return is_valid, "firma file non valida"
        if file is not None:
            is_valid = verify_message_sign(pub_sign, payload_sign, file=file)
        else:
            is_valid = verify_message_sign(pub_sign, payload_sign, payload_seq, payload_kid, payload_kid_cif, payload_id, payload_cif, kids, text)

        return is_valid, "questo messaggio/file e' stato modificato"
    except ValueError:
        return False, "questo messaggio/file e' stato modificato"