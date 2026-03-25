import subprocess, base64, json, os, tempfile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.fernet import Fernet

def _b64url(data: bytes):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64url_decode(data: str):
    padding = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + ("=" * padding))
        
def derive_signing_keys_from_age_private(age_private_key: str):
    
    normalized = (age_private_key or "").strip()
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
        "private_key": _b64url(private_bytes),
        "public_key": _b64url(public_bytes),
        "kid": _b64url(kid),
    }

def calculate_message_sign(private_key_b64url: str, seq = None, kid = None, kid_cif = None, message_id = None, cif = None, kids = None, text = None, file = None):
   
    try:
        private_key_raw = _b64url_decode(private_key_b64url.strip())
    except Exception as exc:
        raise ValueError("Formato chiave privata di firma non valido") from exc

    if len(private_key_raw) != 32:
        raise ValueError("La chiave privata di firma deve essere lunga 32 byte")

    if file is not None:
        payload = {"file": _b64url(file)}
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
    return _b64url(signature)

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
    file = None
) -> bool:
   
    try:
        public_key_raw = _b64url_decode(public_key_b64url.strip())
    except Exception as exc:
        raise ValueError("Formato chiave pubblica di firma non valido") from exc

    if len(public_key_raw) != 32:
        raise ValueError("La chiave pubblica di firma deve essere lunga 32 byte")

    try:
        signature_raw = _b64url_decode(signature_b64url.strip())
    except Exception:
        return False

    

    if file:
        payload = { "file": _b64url(file)}
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

def derivate_master_key(passphrase: str, salt: bytes):
    kdf = Argon2id(salt=salt, length=32, iterations=2, memory_cost=65536, lanes=4)
    raw_key = kdf.derive(passphrase.encode())
    master_key_base64 = base64.urlsafe_b64encode(raw_key)
    return master_key_base64

def encrypt_vault(dic_mess, master_key):
    json_data = json.dumps(dic_mess)
    f = Fernet(master_key)
    encr_blob = f.encrypt(json_data.encode())
    return encr_blob

def decrypt_vault(encr_blob, master_key):
    try:
        f = Fernet(master_key)
        json_data = f.decrypt(encr_blob).decode()
        return json.loads(json_data)
    except Exception as e:
        raise ValueError(f"Errore nella decifrazione del vault: {str(e)}")

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
    
def decrypt_with_age(text, private, decode = True):
    try:
                    
        try:
            text_bytes = base64.b64decode(text)
        except:
            text_bytes = text if isinstance(text, (bytes, bytearray)) else str(text).encode()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
            keyfile.write(private)
            keyfile_path = keyfile.name
        try:
            result = subprocess.run(
                ['age', '-d', '-i', keyfile_path],
                input=text_bytes,
                capture_output=True,
                check=True
            )
            if decode:
                decrypted_text = result.stdout.decode()
            else:
                decrypted_text = result.stdout
        finally:
            os.unlink(keyfile_path)
           
    except Exception:
        
        return None
    
    return decrypted_text

def genera_chiavi():
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
        return public, private
    except subprocess.CalledProcessError:
        return None, None