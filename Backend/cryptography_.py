import subprocess, base64, json, os, hashlib, tempfile, asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

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

def calculate_message_sign(private_key_b64url: str, seq = None, kid = None, kid_cif = None, message_id = None, cif = None, kids = None, text = None, file = None, identity = None):
   
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
        if file is not None:
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

def verify_message_sign(  
    public_key_b64url: str,
    signature_b64url: str,
    seq = None,
    kid = None,
    kid_cif = None,
    message_id = None,
    cif = None,
    kids = None,
    text = None,
    file = None,
    identity = None
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
    try:
        try:
            text_bytes = base64.b64decode(text)
        except:
            text_bytes = text if isinstance(text, (bytes, bytearray)) else str(text).encode()

        if os.name != 'posix':
            raise RuntimeError("Supportato solo su sistemi POSIX")

        # 1. Creiamo la pipe in memoria
        key_read_fd, key_write_fd = os.pipe()
        os.set_inheritable(key_read_fd, True)

        # 2. Scriviamo la chiave nella pipe e chiudiamo il lato di scrittura
        with os.fdopen(key_write_fd, 'wb') as key_pipe:
            key_pipe.write(private.strip().encode('ascii') + b'\n')

        # 3. Lanciamo age passando il testo cifrato su stdin e la chiave dal file descriptor
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
        # Assicuriamoci di chiudere sempre il lato di lettura
        if key_read_fd is not None:
            try:
                os.close(key_read_fd)
            except OSError:
                pass
                
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

async def decrypt_file_with_age_stream(
    encrypted_path: str,
    decrypted_path: str,
    private_age_key: str,
    encrypted_data_offset: int = 0,
    chunk_size: int = 65536,
) -> bytes:
    file_hash = hashlib.sha256()
    key_read_fd = None
    key_write_fd = None
    try:
        if os.name != 'posix':
            raise RuntimeError("Decifratura streaming senza keyfile supportata solo su sistemi POSIX")

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

def calculate_message_sign_stream(private_key_b64url: str, seq=None, kid=None, kid_cif=None, message_id=None, cif=None, kids=None, text=None, file_hash: bytes = None, identity=None):
    try:
        private_key_raw = base64.urlsafe_b64decode(private_key_b64url.strip())
        if identity:
            payload = {"seq": seq, "kid": kid.strip(), "kid_cif": kid_cif.strip(), "id": message_id.strip()}
        elif file_hash:
            payload = {"file_hash": base64.urlsafe_b64encode(file_hash).decode()}
        else:
            sanitized_kids = [str(k).strip() for k in kids] if kids else []
            payload = {"seq": seq, "kid": kid.strip(), "kid_cif": kid_cif.strip(), "id": message_id.strip(), "cif": cif.strip(), "kids": sanitized_kids, "text": text}
        
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signer = Ed25519PrivateKey.from_private_bytes(private_key_raw)
        signature = signer.sign(payload_bytes)
        return base64.urlsafe_b64encode(signature).decode()
    except Exception:
        return None

def verify_message_sign_stream(public_key_b64url: str, signature_b64url: str, seq=None, kid=None, kid_cif=None, message_id=None, cif=None, kids=None, text=None, file_hash: bytes = None, identity=None) -> bool:
    try:
        public_key_raw = base64.urlsafe_b64decode(public_key_b64url.strip())
        if len(public_key_raw) != 32:
            raise ValueError("La chiave pubblica di firma deve essere lunga 32 byte")

        signature_raw = base64.urlsafe_b64decode(signature_b64url.strip())

        if identity:
            payload = {"seq": seq, "kid": kid.strip(), "kid_cif": kid_cif.strip(), "id": message_id.strip()}
        elif file_hash is not None:
            payload = {"file_hash": base64.urlsafe_b64encode(file_hash).decode()}
        else:
            sanitized_kids = [str(k).strip() for k in kids] if kids else []
            payload = {
                "seq": seq,
                "kid": kid.strip(),
                "kid_cif": kid_cif.strip(),
                "id": message_id.strip(),
                "cif": cif.strip(),
                "kids": sanitized_kids,
                "text": text,
            }

        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        verifier = Ed25519PublicKey.from_public_bytes(public_key_raw)
        verifier.verify(signature_raw, payload_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
    
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