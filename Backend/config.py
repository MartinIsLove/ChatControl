import os, base64, tempfile
from dotenv import load_dotenv

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
