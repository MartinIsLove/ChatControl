import os, base64, tempfile
import secrets
from pathlib import Path

from dotenv import load_dotenv

MESSAGE_LIMIT = 4096
SESSION_TIMEOUT = 1200
MAX_INDEX_PER_CHAT = 3000
MAX_REQUESTS = 5
SECONDS_STEP = 60
FILE_DIMENSION_LIMIT = 2 * 1024 * 1024 * 1024
PUBLIC_KEY_COOLDOWN = 10
MAX_MESSAGE_LIMIT = 10000
DOWNLOAD_FAST = 4 * 1024 * 1024
UPLOAD_FAST = 2 * 1024 * 1024

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DOTENV_PATH = _PROJECT_ROOT / ".env"


def _ensure_dotenv_secret_pepper(dotenv_path: Path) -> None:

    if dotenv_path.exists():
        return

    pepper_value = secrets.token_hex(32)
    try:
        with dotenv_path.open("x", encoding="utf-8") as f:
            f.write(f"SECRET_PEPPER={pepper_value}\n")
    except FileExistsError:
        return


_ensure_dotenv_secret_pepper(_DOTENV_PATH)
load_dotenv(dotenv_path=_DOTENV_PATH, override=False)

pepper = os.getenv("SECRET_PEPPER")
if not pepper:
    raise RuntimeError(
        "impostazione del SECRET_PEPPER non riuscita. prova con una riga tipo: SECRET_PEPPER=<valore_esadecimale_casuale_32_caratteri>"
    )

secret_key = base64.urlsafe_b64encode(os.urandom(32))


UPLOAD_DIR = os.path.join(os.getcwd(), "temp_uploads")
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)
tempfile.tempdir = UPLOAD_DIR
