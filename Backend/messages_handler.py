from utils import is_valid_age_public_key, is_group_chat_id
from databaseInteractions import store_public_key_in_vault
# Avoid importing `broadcast_event` at module import time to prevent
# circular imports with `realtime`. We'll import it locally inside
# `handle_in` where needed.

async def handle_in(my_id, msg, data, entity, realtime: bool, temp_id = None):
    chat_id = msg.get('chat_id')
    if my_id and msg.get('sender_id') == my_id:
            msg['is_json'] = False
            msg['text'] = None
            msg['chiave'] = "Questo messaggio e' uno scambio di chiave"
            msg['is_system'] = True
            if realtime and temp_id:
                from realtime import broadcast_event
                payload = {
                    "event_type": "new",
                    "chat_id": chat_id,
                    "message": msg,
                }
                await broadcast_event(temp_id, chat_id, payload)
            return 
    public = msg['json'].get('public')
    kid = msg['json'].get('kid')
    kid_cif = msg['json'].get('kid_cif')
    pub_sign = msg['json'].get('pub_sign')
    if not is_valid_age_public_key(public) or any(t is None for t in (public, kid, kid_cif, pub_sign)):
        msg['error'] = "questo messaggio e' stato modificato"
        if 'json' in msg:
            del msg['json']
        msg['is_json'] = False
        if realtime and temp_id:
            from realtime import broadcast_event
            payload = {
                "event_type": "new",
                "chat_id": chat_id,
                "message": msg,
            }
            await broadcast_event(temp_id, chat_id, payload)
        return 
    store_public_key_in_vault(
        data,
        chat_id,
        msg.get('sender_id'),
        public,
        kid=kid,
        kid_cif=kid_cif,
        pub_sign=pub_sign,
        msg_date=msg.get('date'),
        is_group=is_group_chat_id(chat_id),
        group_title=getattr(entity, 'title', 'Gruppo')
    )
    msg['text'] = None
    msg['chiave'] = "Questo messaggio e' uno scambio di chiave"
    msg['is_system'] = True