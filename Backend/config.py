import os, base64, tempfile
from dotenv import load_dotenv

MESSAGE_LIMIT = 4096
SESSION_TIMEOUT = 1200
MAX_INDEX_PER_CHAT = 3000
MAX_REQUESTS = 5
SECONDS_STEP = 60
FILE_DIMENSION_LIMIT = 1073741824
PUBLIC_KEY_COOLDOWN = 10
MAX_MESSAGE_LIMIT = 10000
DOWNLOAD_FAST = 30 * 1024

load_dotenv()

pepper = os.getenv("SECRET_PEPPER")
secret_key_env = os.getenv("SECRET_KEY")
if secret_key_env:
	secret_key = secret_key_env.encode()
else:
	secret_key = base64.urlsafe_b64encode(os.urandom(32))


UPLOAD_DIR = os.path.join(os.getcwd(), "temp_uploads")
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)
tempfile.tempdir = UPLOAD_DIR
