import os
from dotenv import load_dotenv
import base64, os

load_dotenv()

pepper = os.getenv("SECRET_PEPPER")
secret_key = base64.urlsafe_b64encode(os.urandom(32))