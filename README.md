# installazione e setup

## 1. prerequisiti di sistema

***installa le dipendenze necessarie***
```bash
sudo apt install age openssl python3-pip
```
``` bash
pip install fastapi uvicorn telethon cryptography
 ```
## 2. setup ambiente

***crea un file .env nella cartella principale del progetto come segue:***

```python
SECRET_PEPPER = 9ed4ecb784384de16c2dc5be86818e0b36db355438acd616a45367f50ffca648c4e5793f4b2e3711093b91b54720fb0dc81d11dbed4ceb8c006cdadd5a8efb5d
SECRET_KEY = PgiGSC2uTj3fTcn4nURonH1CZtFhBw6B9Na1I7P7z7k=
```



## 3. generare i certificati

***posizionare i certificati in una cartella ../frontend/certs/ ed in una cartella ../backend/certs***

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes
```

## 3. lanciare il backend

***spostarsi nella cartella backend e lanciare il seguente comando***

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile ./key.pem --ssl-certfile ./cert.pem
```

## 4. lanciare il frontend

***spostarsi nella cartella frontend e lanciare il seguente comando:***

```bash
npm run dev
```
