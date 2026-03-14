import subprocess
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import json
from cryptography.fernet import Fernet
import os
import tempfile

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64url_decode(data: str) -> bytes:
    padding = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + ("=" * padding))

def derive_signing_keys_from_age_private(age_private_key: str) -> dict[str, str]:
    """
    Deriva una chiave di firma Ed25519 deterministica da una AGE private key.

    Ritorna:
    {
        "private_key": <base64url 32 bytes>,
        "public_key": <base64url 32 bytes>,
        "kid": <base64url 16 bytes>
    }
    """
    normalized = (age_private_key or "").strip()
    if not normalized:
        raise ValueError("Chiave privata age mancante")
    if not normalized.startswith("AGE-SECRET-KEY-1"):
        raise ValueError("Formato chiave privata age non valido")

    # HKDF evita uso diretto della stringa come seed della chiave Ed25519.
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

def calcola_firma_messaggio(private_key_b64url: str, seq: int, kid: str, kid_cif: str, message_id: str, cif: str) -> str:
    """
    Calcola una firma Ed25519 del payload canonico {seq, kid, kid_cif, id, cif}.

    Args:
        private_key_b64url: chiave privata di firma (32 byte raw in base64url).
        seq: numero di sequenza del messaggio.
        kid: key id associato alla chiave pubblica di firma.
        kid_cif: key id associato alla chiave di cifratura.
        message_id: identificativo del messaggio.
        cif: flag di cifratura (es. on, file, message).

    Returns:
        Firma base64url (senza padding).
    """
    if not isinstance(private_key_b64url, str) or not private_key_b64url.strip():
        raise ValueError("Chiave privata di firma mancante")
    if not isinstance(seq, int):
        raise ValueError("Il numero di sequenza deve essere un intero")
    if not isinstance(kid, str) or not kid.strip():
        raise ValueError("kid mancante")
    if not isinstance(kid_cif, str) or not kid_cif.strip():
        raise ValueError("kid_cif mancante")
    if not isinstance(message_id, str) or not message_id.strip():
        raise ValueError("id messaggio mancante")
    if not isinstance(cif, str) or not cif.strip():
        raise ValueError("flag cifratura mancante")

    try:
        private_key_raw = _b64url_decode(private_key_b64url.strip())
    except Exception as exc:
        raise ValueError("Formato chiave privata di firma non valido") from exc

    if len(private_key_raw) != 32:
        raise ValueError("La chiave privata di firma deve essere lunga 32 byte")

    payload = {
        "seq": seq,
        "kid": kid.strip(),
        "kid_cif": kid_cif.strip(),
        "id": message_id.strip(),
        "cif": cif.strip(),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    signer = Ed25519PrivateKey.from_private_bytes(private_key_raw)
    signature = signer.sign(payload_bytes)
    return _b64url(signature)

def verifica_firma_messaggio(
        
    public_key_b64url: str,
    seq: int,
    kid: str,
    kid_cif: str,
    message_id: str,
    cif: str,
    signature_b64url: str,
) -> bool:
    """
    Verifica una firma Ed25519 del payload canonico {seq, kid, kid_cif, id, cif}.

    Args:
        public_key_b64url: chiave pubblica di firma (32 byte raw in base64url).
        seq: numero di sequenza del messaggio.
        kid: key id associato alla chiave pubblica di firma.
        kid_cif: key id associato alla chiave di cifratura.
        message_id: identificativo del messaggio.
        cif: flag di cifratura (es. on, file, message).
        signature_b64url: firma base64url (senza padding).

    Returns:
        True se la firma e' valida, False altrimenti.
    """
    if not isinstance(public_key_b64url, str) or not public_key_b64url.strip():
        raise ValueError("Chiave pubblica di firma mancante")
    if not isinstance(seq, int):
        raise ValueError("Il numero di sequenza deve essere un intero")
    if not isinstance(kid, str) or not kid.strip():
        raise ValueError("kid mancante")
    if not isinstance(kid_cif, str) or not kid_cif.strip():
        raise ValueError("kid_cif mancante")
    if not isinstance(message_id, str) or not message_id.strip():
        raise ValueError("id messaggio mancante")
    if not isinstance(cif, str) or not cif.strip():
        raise ValueError("flag cifratura mancante")
    if not isinstance(signature_b64url, str) or not signature_b64url.strip():
        raise ValueError("Firma mancante")

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

    payload = {
        "seq": seq,
        "kid": kid.strip(),
        "kid_cif": kid_cif.strip(),
        "id": message_id.strip(),
        "cif": cif.strip(),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    verifier = Ed25519PublicKey.from_public_bytes(public_key_raw)
    try:
        verifier.verify(signature_raw, payload_bytes)
        return True
    except InvalidSignature:
        return False
    
def deriva_master_key(passphrase: str, salt: bytes):
    kdf = Argon2id(salt=salt, length=32, iterations=2, memory_cost=65536, lanes=4)
    raw_key = kdf.derive(passphrase.encode())
    master_key_base64 = base64.urlsafe_b64encode(raw_key)
    return master_key_base64

def cifra_vault(dinizionario, master_key):
    json_data = json.dumps(dinizionario)
    f = Fernet(master_key)
    blob_cifrato = f.encrypt(json_data.encode())
    return blob_cifrato

def decifra_vault(blob_cifrato, master_key):
    try:
        f = Fernet(master_key)
        json_data = f.decrypt(blob_cifrato).decode()
        return json.loads(json_data)
    except Exception as e:
        raise ValueError(f"Errore nella decifrazione del vault: {str(e)}")

def cifra_con_age(plaintext: str | bytes, public_keys: list):
    
    try:
        # Costruisci argomenti age: -r for each recipient
        args = ['age']
        for key in public_keys:
            args.extend(['-r', key])
        
        # Esegui age con input/output binario
        if isinstance(plaintext, bytes):
            input_data = plaintext
        else:
            input_data = plaintext.encode()
        
        result = subprocess.run(args, input=input_data, capture_output=True, check=True)
        ciphertext = result.stdout
        
        # Converti in base64 per trasmissione sicura
        return base64.b64encode(ciphertext).decode()
    except subprocess.CalledProcessError as e:
        print(f"Errore cifratura age: {e.stderr}")
        return None

def decifra_file_con_age(ciphertext, candidate_privates):
    for privata in candidate_privates:
        try:
            try:
                input_bytes = base64.b64decode(ciphertext)
            except Exception:
                input_bytes = ciphertext if isinstance(ciphertext, (bytes, bytearray)) else str(ciphertext).encode()

            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                keyfile.write(privata)
                keyfile_path = keyfile.name
            try:
                result = subprocess.run(
                    ['age', '-d', '-i', keyfile_path],
                    input=input_bytes,
                    capture_output=True,
                    check=True
                )
                return result.stdout
            finally:
                os.unlink(keyfile_path)
        except Exception:
            continue
    return None

def genera_chiavi():
    try:
        risultato = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True)
        output = risultato.stdout
        linee = output.splitlines()
        pubblica = ""
        privata = ""
        for linea in linee:
            if linea.startswith("# public key:"):
                pubblica = linea.split(":")[1].strip()
            elif linea.startswith("AGE-SECRET-KEY-1"):
                privata = linea.strip()
        return pubblica, privata
    except subprocess.CalledProcessError:
        print("Errore: age-keygen non è installato. Usa 'sudo apt install age'")
        return None, None
    