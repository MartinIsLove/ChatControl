import os, base64
from dotenv import load_dotenv

load_dotenv()

pepper = os.getenv("SECRET_PEPPER")
secret_key_env = os.getenv("SECRET_KEY")
if secret_key_env:
	secret_key = secret_key_env.encode()
else:
	secret_key = base64.urlsafe_b64encode(os.urandom(32))