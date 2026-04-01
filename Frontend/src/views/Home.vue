<script>
  import api from '@/services/api'
  import lottie from 'lottie-web'
  import pako from 'pako'
     export default {
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                file: null,
                chats: [],
                selectedChat: null,
                messaggi: [],
                text: '',
                useAltSend: false,
                chatsInterval: null,
                chatReloadInterval: null,
                animatedStickerNodes: {},
                animatedStickerLoaded: new Set(),
                pageSize: 50,
                olderPageSize: 20,
                loadingOlder: false,
                hasMoreOlder: true,
                lastChatsAt: 0,
                chatsInFlight: false,
                dist : false,
                ws: null,
                wsChatId: null,
                realtimeReloadTimer: null,
                contextMenuVisible: false,
                contextMenuPos: { x: 0, y: 0 },
                contextMenuMessage: null,
                longPressTimer: null,
                longPressStart: null,
                longPressDelay: 550,
                sendingMessage: false,
                sendingEncryptedFile: false,
                downloadingFile: false,
                downloadingFileName: '',
                optimisticCounter: 0,
            }
        },
        methods: {
            newOptimisticId() {
              this.optimisticCounter += 1
              return `tmp-${Date.now()}-${this.optimisticCounter}`
            },
            createOptimisticMessage({ text = '', file = null, secure = false }) {
              if (!this.selectedChat) return null

              const nowIso = new Date().toISOString()
              const tempId = this.newOptimisticId()
              const hasFile = !!file

              return {
                id: tempId,
                chat_id: this.selectedChat.id,
                text: text || '',
                date: nowIso,
                sender_id: 'me',
                sender_username: null,
                out: true,
                reply_to: null,
                file: hasFile,
                filename: hasFile ? file.name : null,
                mime: hasFile ? (file.type || 'application/octet-stream') : null,
                size: hasFile ? file.size : null,
                media_type: hasFile ? 'document' : null,
                secure,
                pending: true,
              }
            },
            appendOptimisticMessage(message) {
              if (!message) return
              this.messaggi = [...this.messaggi, message]
              if (!this.dist) {
                this.scrollToBottom()
              }
            },
            resolveOptimisticMessage(tempId) {
              if (!tempId) return
              const idx = this.messaggi.findIndex((m) => m.id === tempId)
              if (idx === -1) return
              const current = this.messaggi[idx]
              this.messaggi.splice(idx, 1, { ...current, pending: false })
            },
            replaceOptimisticId(tempId, realId) {
              if (!tempId) return
              const idx = this.messaggi.findIndex((m) => m.id === tempId)
              if (idx === -1) return
              const current = this.messaggi[idx]
              this.messaggi.splice(idx, 1, { ...current, id: realId, pending: false })
            },
            failOptimisticMessage(tempId, detail) {
              if (!tempId) return
              const idx = this.messaggi.findIndex((m) => m.id === tempId)
              if (idx === -1) return
              const current = this.messaggi[idx]
              const errorText = detail || 'Invio fallito'
              this.messaggi.splice(idx, 1, {
                ...current,
                pending: false,
                error: errorText,
              })
            },
            findMatchingOptimisticMessageIndex(message) {
              return this.findMatchingOptimisticInList(this.messaggi, message)
            },
            findMatchingOptimisticInList(list, message) {
              if (!Array.isArray(list) || !message || !message.out) return -1
              const normalizedText = (message.text || '').trim()
              const hasFile = !!message.file

              return list.findIndex((m) => {
                // MODIFICA: Accetta il match se è "pending" OPPURE se ha ancora un ID temporaneo
                const isTempId = String(m?.id).startsWith('tmp-');
                if (!(m?.pending || isTempId) || !m?.out) return false;
                
                if (!!m.file !== hasFile) return false
                if ((m.text || '').trim() !== normalizedText) return false
                if (hasFile && (m.filename || '') !== (message.filename || '')) return false
                return true
              })
            },
            startChatEvents(chatId) {
              if (this.ws && this.wsChatId === chatId) return
              this.stopChatEvents()

              const ws = new WebSocket(`${__WEBSOCKETURL__}/ws/chats/${chatId}`)
              this.ws = ws
              this.wsChatId = chatId

              ws.onmessage = (event) => {
                try {
                  console.log("[WS] Messaggio ricevuto raw:", event.data)
                  const payload = JSON.parse(event.data)
                  console.log("[WS] Payload parsed:", payload)
                  this.handleChatEvent(payload)
                } catch (e) {
                  console.error('[WS] Errore parsing evento WS:', e)
                }
              }

              ws.onclose = () => {
                if (this.ws === ws) {
                  this.ws = null
                  this.wsChatId = null
                }
              }
            },
            stopChatEvents() {
              if (this.ws) {
                this.ws.close()
                this.ws = null
                this.wsChatId = null
              }
              if (this.realtimeReloadTimer) {
                clearTimeout(this.realtimeReloadTimer)
                this.realtimeReloadTimer = null
              }
            },
            handleChatEvent(payload) {
              console.log("[WS] handleChatEvent chiamato con:", payload)
              if (payload.event_type === 'upload_success') {
                console.log("[WS] Upload completato con successo per:", payload.temp_msg_id)
                this.replaceOptimisticId(payload.temp_msg_id, payload.message_id)
                return
              }
              if (payload.event_type === 'upload_error') {
                console.log("[WS] Errore di upload:", payload.error)
                this.failOptimisticMessage(payload.temp_msg_id, payload.error)
                return
              }
              if (!payload || !this.selectedChat) {
                console.log("[WS] handleChatEvent: payload o selectedChat mancante")
                return
              }
              if (payload.chat_id !== this.selectedChat.id) {
                console.log(`[WS] handleChatEvent: chat_id mismatch (payload: ${payload.chat_id}, selected: ${this.selectedChat.id})`)
                return
              }
              if (payload.event_type === 'new') {
                console.log("[WS] handleChatEvent: event_type 'new'")
                const message = payload.message
                if (!message || !message.id) {
                  console.log("[WS] handleChatEvent: message o id mancante")
                  return false
                }

                if (!message.chat_id) {
                  message.chat_id = payload.chat_id
                }

                const optimisticIndex = this.findMatchingOptimisticMessageIndex(message)
                if (optimisticIndex !== -1) {
                  const optimistic = this.messaggi[optimisticIndex]
                  this.messaggi.splice(optimisticIndex, 1, {
                    ...optimistic,
                    ...message,
                    pending: false,
                  })
                  return true
                }

                const index = this.messaggi.findIndex((m) => m.id === message.id)
                if (index === -1) {
                  this.messaggi = [...this.messaggi, message]
                  return true
                }

                const current = this.messaggi[index]
                this.messaggi.splice(index, 1, { ...current, ...message })
                return true
              }
              if (payload.event_type === 'edited') {
                console.log("[WS] handleChatEvent: event_type 'edited'")
                this.reloadEditedMessage(payload)
                return
              }
              const changed = this.applyChatEvent(payload)
              if (!changed) {
                console.log("[WS] handleChatEvent: nessun cambiamento, queueRealtimeReload")
                this.queueRealtimeReload()
                return
              }
              if (payload.event_type === 'new' && !this.dist) {
                this.scrollToBottom()
              }
            },
            applyChatEvent(payload) {
              const type = payload.event_type
              if (type === 'deleted') {
                const ids = Array.isArray(payload.message_ids) ? payload.message_ids : []
                if (ids.length === 0) return false
                const before = this.messaggi.length
                this.messaggi = this.messaggi.filter((m) => !ids.includes(m.id)) //filtra via id cancellati
                for (const id of ids) {
                  this.animatedStickerLoaded.delete(id)
                  delete this.animatedStickerNodes[id]
                }
                return this.messaggi.length !== before
              }

              const message = payload.message
              if (!message || !message.id) return false

              if (!message.chat_id) {
                message.chat_id = payload.chat_id
              }

              const optimisticIndex = this.findMatchingOptimisticMessageIndex(message)
              if (optimisticIndex !== -1) {
                const optimistic = this.messaggi[optimisticIndex]
                this.messaggi.splice(optimisticIndex, 1, {
                  ...optimistic,
                  ...message,
                  pending: false,
                })
                return true
              }

              const index = this.messaggi.findIndex((m) => m.id === message.id)
              if (index === -1) {
                this.messaggi = [...this.messaggi, message]
                return true
              }

              const current = this.messaggi[index]
              this.messaggi.splice(index, 1, { ...current, ...message })
              return true
            },
            queueRealtimeReload(options = null) {
              if (this.realtimeReloadTimer) {
                clearTimeout(this.realtimeReloadTimer)
                this.realtimeReloadTimer = null
              }
              this.reload_chat(true, options)
            },
            setAnimatedStickerRef(messageId, el) {
              if (el) {
                this.animatedStickerNodes[messageId] = el
              }
            },
            mediaUrl(messageId, chatId) {
              const resolvedChatId = chatId ?? this.selectedChat?.id
              if (!resolvedChatId) return ''
              return `${__API_URL__}/media/download/${resolvedChatId}/${messageId}`
            },
            async initAnimatedStickers() {
              if (!this.selectedChat) return
              const chatId = this.selectedChat.id
              const targets = this.messaggi.filter(
                (m) => m.media_type === 'sticker_animated' && (!m.mime || m.mime === 'application/x-tgsticker')
              )
              for (const m of targets) {
                if (!this.selectedChat || this.selectedChat.id !== chatId) return
                if (this.animatedStickerLoaded.has(m.id)) continue
                const container = this.animatedStickerNodes[m.id]
                if (!container) continue
                try {
                  const res = await fetch(this.mediaUrl(m.id, m.chat_id || chatId), { credentials: 'include' })
                  if (!res.ok) continue
                  const buffer = await res.arrayBuffer()
                  const jsonStr = pako.inflate(new Uint8Array(buffer), { to: 'string' })
                  const animationData = JSON.parse(jsonStr)
                  container.innerHTML = ''
                  lottie.loadAnimation({
                    container,
                    renderer: 'svg',
                    loop: true,
                    autoplay: true,
                    animationData
                  })
                  this.animatedStickerLoaded.add(m.id)
                } catch (e) {
                  console.error('Errore caricamento sticker animato:', e)
                }
              }
            },
            removeFile() {
              this.file = null;
              this.$refs.fileInput.value = '';
            },
            focusMessageInput() {
              this.$nextTick(() => {
                const messageInput = this.$refs.messageInput
                if (messageInput && !messageInput.disabled) {
                  messageInput.focus()
                }
              })
            },
            handleFileChange(event) {
              this.file = event.target.files[0];
            },
            async get_chats(){
              const now = Date.now()
              if (this.chatsInFlight || now - this.lastChatsAt < 5000) return
              this.errormsg = null
              this.loading = true
              this.chatsInFlight = true
              let response
              try {
                  response = await api.get('/chats', { withCredentials: true })
                  console.log('chat requested:', response.data)
                  this.chats = response.data.chats
                this.lastChatsAt = now
              } catch (e) {
                  this.errormsg = e.response?.data?.detail || e.message
                  if(this.errormsg === "Sessione scaduta. Riesegui il login."){
                    this.$router.push('/')
                  }
              } finally {
                this.chatsInFlight = false
                  this.loading = false
              }
            },
            async logoutUser() {
              try {
                await api.post('/logout')
              } catch (e) {
                console.warn('Logout failed:', e?.message || e)
              } finally {
                this.$router.push('/')
              }
            },
            async selectChat(chat) {
              if (this.selectedChat && this.selectedChat.id === chat.id) {
                return
              }
              this.closeMessageMenu()
              this.selectedChat = chat
              this.loading = true
              this.startChatEvents(chat.id)
              let response

              // Reset animated stickers quando cambi chat
              this.animatedStickerLoaded.clear()
              this.animatedStickerNodes = {}
              this.loadingOlder = false
              this.hasMoreOlder = true
              this.messaggi = []

                try {
                  await this.init_chat(chat)
                  response = await api.get(`/chats/${chat.id}/limit/${this.pageSize}/start/0`, { withCredentials: true })
                  console.log('messaggi ricevuti:', response.data)
                  this.messaggi = response.data.messages
                  this.hasMoreOlder = (response.data.messages || []).length > 0
                  
                  this.scrollToBottom()
                  
                  // Carica sticker animati dopo che il DOM è renderizzato
                  this.$nextTick(() => {
                    setTimeout(() => this.initAnimatedStickers(), 100)
                  })
              } catch (e) {
                  this.errormsg = e.response?.data?.detail || e.message
                  if(this.errormsg === "Sessione scaduta. Riesegui il login."){
                    this.$router.push('/')
                  }
              } finally {
                  this.loading = false
              }
            },
            async reload_chat(force = false, options = null){
              const now = Date.now()
                this.loading = true
              let response
              let chat = this.selectedChat
              const start = options?.start ?? 0
              const limit = options?.limit ?? this.pageSize
              try {
                  response = await api.get(`/chats/${chat.id}/limit/${limit}/start/${start}`, { withCredentials: true })
                  console.log('messaggi ricevuti:', response.data)
                  this.mergeLatestMessages(response.data.messages)
                return response.data.messages || []
              } catch (e) {
                  this.errormsg = e.response?.data?.detail || e.message
                  if(this.errormsg === "Sessione scaduta. Riesegui il login."){
                    this.$router.push('/')
                  }
              } finally {
                  this.loading = false
              }
              return null
            },
            async fetchLatestMessages(limit = 1) {
              if (!this.selectedChat) return
              try {
                const response = await api.get(
                  `/chats/${this.selectedChat.id}/limit/${limit}/start/0`,
                  { withCredentials: true }
                )
                this.mergeLatestMessages(response.data.messages)
              } catch (e) {
                this.errormsg = e.response?.data?.message || e.message
              }
            },
            async reloadEditedMessage(payload) {
              const messageId = payload?.message?.id
              if (!this.selectedChat || !messageId) {
                this.queueRealtimeReload()
                return
              }

              const idx = this.messaggi.findIndex((m) => m.id === messageId)
              if (idx === -1) {
                this.queueRealtimeReload()
                return
              }

              const start = Math.max(0, this.messaggi.length - 1 - idx)
              const limit = start + 1
              try {
                const updated = await this.reload_chat(true, { start, limit })
                if (!updated || updated.length === 0) {
                  this.queueRealtimeReload()
                }
              } catch (e) {
                console.error('Errore reload messaggio editato:', e)
                this.queueRealtimeReload()
              }
            },
            mergeLatestMessages(latestMessages) {
              if (!Array.isArray(latestMessages) || latestMessages.length === 0) return
              if (this.messaggi.length === 0) {
                this.messaggi = latestMessages
                return
              }

              const existingIndex = new Map(this.messaggi.map((m, i) => [m.id, i]))
              const merged = [...this.messaggi]
              let changed = false

              for (const msg of latestMessages) {
                const optimisticIndex = this.findMatchingOptimisticInList(merged, msg)
                if (optimisticIndex !== -1 && msg?.out) {
                  merged.splice(optimisticIndex, 1, { ...merged[optimisticIndex], ...msg, pending: false })
                  changed = true
                  continue
                }

                const idx = existingIndex.get(msg.id)
                if (idx === undefined) {
                  merged.push(msg)
                  changed = true
                  continue
                }

                merged[idx] = { ...merged[idx], ...msg }
                changed = true
              }

              if (changed) {
                this.messaggi = merged
              }
            },
            async loadOlderMessages() {
              if (!this.selectedChat || this.loadingOlder || !this.hasMoreOlder) return

              const messagesDiv = this.$refs.messagesContainer
              const prevScrollHeight = messagesDiv ? messagesDiv.scrollHeight : 0
              const prevScrollTop = messagesDiv ? messagesDiv.scrollTop : 0

              this.loadingOlder = true
              try {
                const start = this.messaggi.length
                const response = await api.get(
                  `/chats/${this.selectedChat.id}/limit/${this.olderPageSize}/start/${start}`,
                  { withCredentials: true }
                )
                const older = response.data.messages || []
                if (older.length === 0) {
                  this.hasMoreOlder = false
                  return
                }

                this.messaggi = [...older, ...this.messaggi]

                this.$nextTick(() => {
                  if (!messagesDiv) return
                  const newScrollHeight = messagesDiv.scrollHeight
                  messagesDiv.scrollTop = newScrollHeight - prevScrollHeight + prevScrollTop
                })
              } catch (e) {
                this.errormsg = e.response?.data?.message || e.message
              } finally {
                this.loadingOlder = false
              }
            },
            async sendMessage(){
              if (!this.selectedChat) {
                return
              }
              if (this.sendingEncryptedFile || this.sendingMessage) {
                this.errormsg = 'Attendi: invio file cifrato in corso'
                return
              }
              this.sendingMessage = true
              this.loading = true
              const outgoingText = this.text
              const outgoingFile = this.file
              const optimisticMessage = this.createOptimisticMessage({ text: outgoingText, file: outgoingFile, secure: false })
              const optimisticId = optimisticMessage?.id
              this.appendOptimisticMessage(optimisticMessage)

              this.file = null
              if (this.$refs.fileInput) {
                this.$refs.fileInput.value = ''
              }
              this.text = ''
              try {
                if(outgoingFile && outgoingText){

                  const formData = new FormData()
                  formData.append('file',outgoingFile)
                  formData.append('text', outgoingText || '')
                  formData.append('chat_id',this.selectedChat.id)
                  formData.append('cryph',false)
                  formData.append('group',this.selectedChat.is_group)
                  formData.append('temp_msg_id', optimisticId) 

                  await api.post('/messages/send/file', formData, { withCredentials: true })
                  
                }
                else if(outgoingFile && !outgoingText){
                  const formData = new FormData()
                  formData.append('file',outgoingFile)
                  formData.append('text', outgoingText || '')
                  formData.append('chat_id',this.selectedChat.id)
                  formData.append('cryph',false)
                  formData.append('group',this.selectedChat.is_group)
                  formData.append('temp_msg_id', optimisticId) 

                  await api.post('/messages/send/file', formData, { withCredentials: true })
                }
                else if(outgoingText.trim().length !== 0){
                  const resp = await api.post('/messages/send', {
                    text: outgoingText,
                    chat_id: this.selectedChat.id,
                    cryph: false,
                    group: this.selectedChat.is_group
                  }, { withCredentials: true })
                  
                  if (resp.data && resp.data.message_id) {
                    this.replaceOptimisticId(optimisticId, resp.data.message_id)
                  } else {
                    this.resolveOptimisticMessage(optimisticId)
                  }
                }
              } catch (e) {
                  this.errormsg = e.response?.data?.detail || e.message
                  this.failOptimisticMessage(optimisticId, this.errormsg)
                  if(this.errormsg === "Sessione scaduta. Riesegui il login."){
                    this.$router.push('/')
                  }
              } finally {
                  this.loading = false
                  this.sendingMessage = false
                  this.scrollToBottom()
                  this.focusMessageInput()
              }
            },
            async handleSubmit(){
              if (this.sendingMessage || this.sendingEncryptedFile) {
                return
              }
              if (this.useAltSend) {
                await this.sendChyp()
              } else {
                await this.sendMessage()
              }
            },
            async sendChyp(){
              if (!this.selectedChat) {
                return
              }
              if (this.sendingMessage || this.sendingEncryptedFile || (!this.file && !this.text.trim())) return;

              this.sendingMessage = true
              this.loading = true
              const outgoingText = this.text
              const outgoingFile = this.file
              const optimisticMessage = this.createOptimisticMessage({ text: outgoingText, file: outgoingFile, secure: true })
              const optimisticId = optimisticMessage?.id
              this.appendOptimisticMessage(optimisticMessage)

              this.file = null
              if (this.$refs.fileInput) {
                this.$refs.fileInput.value = ''
              }
              this.text = ''

              if (!outgoingFile && outgoingText.trim().length !== 0){
                try {
                    const resp = await api.post('/messages/send', {
                      text: outgoingText,
                      chat_id: this.selectedChat.id,
                      cryph: true,
                      group: this.selectedChat.is_group
                    }, { withCredentials: true })
                    
                    // MODIFICA: Aggiorna l'ID se presente, altrimenti risolvi normalmente
                    if (resp.data && resp.data.message_id) {
                      this.replaceOptimisticId(optimisticId, resp.data.message_id)
                    } else {
                      this.resolveOptimisticMessage(optimisticId)
                    }
                    this.scrollToBottom()
                } catch (e) {
                    this.errormsg = e.response?.data?.message || e.message
                    this.failOptimisticMessage(optimisticId, this.errormsg)
                } finally {
                    this.loading = false
                    this.sendingMessage = false
                  this.focusMessageInput()
                }
              }
              else{
                if(outgoingFile && outgoingText){
                  this.sendingEncryptedFile = true

                  const formData = new FormData()
                  formData.append('file',outgoingFile)
                  formData.append('text', outgoingText || '')
                  formData.append('chat_id',this.selectedChat.id)
                  formData.append('cryph',true)
                  formData.append('group',this.selectedChat.is_group)
                  formData.append('temp_msg_id', optimisticId) // <-- AGGIUNGI QUESTO
                  
                  try{
                    await api.post('/messages/send/file', formData, { withCredentials: true })
                  }
                  catch(e){
                    this.errormsg = e.response?.data?.message || e.message
                    this.failOptimisticMessage(optimisticId, this.errormsg)
                  }
                  finally{
                    this.loading = false
                    this.sendingMessage = false
                    this.sendingEncryptedFile = false
                    this.scrollToBottom()
                    this.focusMessageInput()
                  }
                }
                else if(outgoingFile && !outgoingText){
                  this.sendingEncryptedFile = true

                  const formData = new FormData()
                  formData.append('file',outgoingFile)
                  formData.append('text', outgoingText || '')
                  formData.append('chat_id',this.selectedChat.id)
                  formData.append('cryph',true)
                  formData.append('group',this.selectedChat.is_group)
                  formData.append('temp_msg_id', optimisticId) // <-- AGGIUNGI QUESTO
                  
                  try{
                    await api.post('/messages/send/file', formData, { withCredentials: true })
                    // ELIMINATO: if (resp?.data?.message_id) this.replaceOptimisticId...
                  }
                  catch(e){
                    this.errormsg = e.response?.data?.message || e.message
                    this.failOptimisticMessage(optimisticId, this.errormsg)
                  }
                  finally{
                    this.loading = false
                    this.sendingMessage = false
                    this.sendingEncryptedFile = false
                    this.scrollToBottom()
                    this.focusMessageInput()
                  }
                }
              }
            },
            async sendkey(){
              if (!this.selectedChat) {
                return
              }
              this.loading = true
              try {
                  await api.post('/messages/initializing', {
                    chat_id: this.selectedChat.id
                  }, { withCredentials: true })
                  await this.fetchLatestMessages(1)
              } catch (e) {
                  this.errormsg = e.response?.data?.message || e.message
              } finally {
                  this.loading = false
              }
            },
            async init_chat(chat){
              let response
              try {
                  response = await api.get(`/chats/${chat.id}/inits`, { withCredentials: true })
                  console.log('init chat:', response.data)
              } catch (e) {
                  this.errormsg = e.response?.data?.detail || e.message
                  if(this.errormsg === "Sessione scaduta. Riesegui il login."){
                    this.$router.push('/')
                  }
              }
            },
            scrollToBottom() {
              this.$nextTick(() => {
                const messagesDiv = this.$refs.messagesContainer
                if (messagesDiv) {
                  messagesDiv.scrollTop = messagesDiv.scrollHeight
                }
              })
            },
            handleMessagesScroll() {
              if (this.contextMenuVisible) {
                this.closeMessageMenu()
              }
              const messagesDiv = this.$refs.messagesContainer
              if (!messagesDiv || this.messaggi.length === 0) return

              const threshold = 8

              const distanceFromBottom = messagesDiv.scrollHeight - (messagesDiv.scrollTop + messagesDiv.clientHeight)
              this.dist = distanceFromBottom > 200
              if (messagesDiv.scrollTop <= threshold) {
                this.loadOlderMessages()
              }
            },
            formatFileSize(bytes) {
              if (!bytes) return '0 B'
              const k = 1024
              if (bytes < k) return bytes + ' B'
              if (bytes < k * k) return (bytes / k).toFixed(1) + ' KB'
              if (bytes < k * k * k) return (bytes / (k * k)).toFixed(1) + ' MB'
              return (bytes / (k * k * k)).toFixed(1) + ' GB'
            },
            openMessageMenu(event, message) {
              if (!message) return
              event.preventDefault()
              event.stopPropagation()
              this.openMessageMenuAt(event.clientX, event.clientY, message)
            },
            openMessageMenuAt(x, y, message) {
              this.contextMenuVisible = true
              this.contextMenuMessage = message
              this.contextMenuPos = { x, y }
              this.$nextTick(() => this.adjustMessageMenuPosition())
            },
            adjustMessageMenuPosition() {
              const menu = this.$refs.messageContextMenu
              if (!menu) return
              const rect = menu.getBoundingClientRect()
              const padding = 8
              let x = this.contextMenuPos.x
              let y = this.contextMenuPos.y

              if (x + rect.width + padding > window.innerWidth) {
                x = window.innerWidth - rect.width - padding
              }
              if (y + rect.height + padding > window.innerHeight) {
                y = window.innerHeight - rect.height - padding
              }
              if (x < padding) x = padding
              if (y < padding) y = padding

              this.contextMenuPos = { x, y }
            },
            closeMessageMenu() {
              this.contextMenuVisible = false
              this.contextMenuMessage = null
              this.clearLongPressTimer()
            },
            async handleMessageAction(action) {
              const message = this.contextMenuMessage
              if (!message) return

              if (action === 'reply') {
                const senderName = message.out ? 'Tu' : (message.sender_username || message.sender_id || 'utente')
                const body = message.text ? message.text.trim() : ''
                const replyText = body ? `@${senderName}: ${body}` : `@${senderName}:`
                this.text = this.text ? `${this.text} ${replyText}` : replyText
              } else {
                this.errormsg = 'Azione non ancora disponibile'
              }
              if (action === 'delete') {
                if (String(message.id).startsWith('tmp-')) {
                  this.messaggi = this.messaggi.filter((m) => m.id !== message.id)
                  this.closeMessageMenu()
                  return
                }
                try {
                  const response = await api.post(
                    `/messages/delete`,
                    { chat_id: this.selectedChat.id, message_id: message.id },
                    { withCredentials: true }
                  )
                  if (response?.data?.status === 'ok') {
                    this.messaggi = this.messaggi.filter((m) => m.id !== message.id)
                    this.animatedStickerLoaded.delete(message.id)
                    delete this.animatedStickerNodes[message.id]
                  } else {
                    this.errormsg = response?.data?.detail || 'Cancellazione fallita'
                  }
                } catch (e) {
                  this.errormsg = e.response?.data?.message || e.message
                } finally {
                  this.loading = false
                }
              }

              this.closeMessageMenu()
            },
            handleMessageTouchStart(event, message) {
              if (!event.touches || event.touches.length !== 1) return
              const touch = event.touches[0]
              this.longPressStart = { x: touch.clientX, y: touch.clientY }
              this.clearLongPressTimer()
              this.longPressTimer = setTimeout(() => {
                this.openMessageMenuAt(touch.clientX, touch.clientY, message)
              }, this.longPressDelay)
            },
            handleMessageTouchMove(event) {
              if (!this.longPressTimer || !this.longPressStart || !event.touches || event.touches.length !== 1) return
              const touch = event.touches[0]
              const dx = Math.abs(touch.clientX - this.longPressStart.x)
              const dy = Math.abs(touch.clientY - this.longPressStart.y)
              if (dx + dy > 12) {
                this.clearLongPressTimer()
              }
            },
            handleMessageTouchEnd() {
              this.clearLongPressTimer()
            },
            clearLongPressTimer() {
              if (this.longPressTimer) {
                clearTimeout(this.longPressTimer)
                this.longPressTimer = null
              }
            },
            async handleFileClick(message) {
              if (!this.selectedChat || !message || !message.id) return
              if (this.downloadingFile) return

              this.downloadingFile = true
              this.downloadingFileName = message.filename || 'file'

              const parseFilename = (contentDisposition) => {
                if (!contentDisposition) return null
                const utf8Match = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i)
                if (utf8Match && utf8Match[1]) {
                  try {
                    return decodeURIComponent(utf8Match[1])
                  } catch {
                    return utf8Match[1]
                  }
                }
                const asciiMatch = contentDisposition.match(/filename="?([^";]+)"?/i)
                return asciiMatch && asciiMatch[1] ? asciiMatch[1] : null
              }

              const tryDownload = async (url) => {
                const res = await fetch(url, { credentials: 'include' })
                if (!res.ok) return { ok: false, status: res.status }
                const blob = await res.blob()
                const headerName = parseFilename(res.headers.get('content-disposition'))
                const filename = headerName || message.filename || 'file'
                this.downloadingFileName = filename

                const blobUrl = window.URL.createObjectURL(blob)
                const link = document.createElement('a')
                link.href = blobUrl
                link.download = filename
                document.body.appendChild(link)
                link.click()
                link.remove()
                window.URL.revokeObjectURL(blobUrl)
                return { ok: true }
              }

              try {
                const encryptedUrl = `${__API_URL__}/media/cifrato/download/${this.selectedChat.id}/${message.id}`
                const plainUrl = `${__API_URL__}/media/download/${this.selectedChat.id}/${message.id}`

                  const mustUseEncrypted = Boolean(message?.secure) || this.isEncryptedPayload(message)
                  let result = await tryDownload(mustUseEncrypted ? encryptedUrl : plainUrl)
                if (!result.ok) {
                  this.errormsg = `Download fallito (${result.status})`
                }
              } catch (e) {
                this.errormsg = e.message || 'Download fallito'
              } finally {
                this.downloadingFile = false
                this.downloadingFileName = ''
              }
            },
            isEncryptedPayload(message) {
              if (!message || !message.text) return false
              try {
                const parsed = JSON.parse(message.text)
                const flag = parsed?.CIF || parsed?.cif
                return flag === 'on' || flag === 'file' || flag === 'message' || flag === 'in'
              } catch {
                return false
              }
            },
        },
        watch: {
          messaggi: {
            handler() {
              this.$nextTick(() => this.initAnimatedStickers())
            },
            deep: true
          }
        },
        mounted() {
            this.get_chats()
            this.chatsInterval = setInterval(() => {
                this.get_chats()
            }, 20000)
            /*this.chatReloadInterval = setInterval(() => {
                if (this.selectedChat) {
                    this.reload_chat()
                }
            }, 5000)*/
        },
        beforeUnmount() {
            if (this.chatsInterval) clearInterval(this.chatsInterval)
            if (this.chatReloadInterval) clearInterval(this.chatReloadInterval)
          this.clearLongPressTimer()
          this.stopChatEvents()
        }
    }
</script>
<template>
    <div class="container-fluid vh-100">
    <div class="row h-100">
      
      <div class="col-md-4 col-lg-3 border-end p-0 bg-light d-flex flex-column h-100">
        <div class="p-3 border-bottom bg-white d-flex align-items-center gap-2">
          <button
            class="btn p-0 border-0 bg-transparent"
            type="button"
            data-bs-toggle="offcanvas"
            data-bs-target="#offcanvasWithBothOptions"
            aria-controls="offcanvasWithBothOptions"
          >
            <img src="/menu.svg" alt="Menu" style="width: 20px; height: 20px;">
          </button>
          <h5 class="mb-0">Le mie Chat</h5>
        </div>

        <div
          class="offcanvas offcanvas-start"
          data-bs-scroll="true"
          tabindex="-1"
          id="offcanvasWithBothOptions"
          aria-labelledby="offcanvasWithBothOptionsLabel"
        >
          <div class="offcanvas-header">
            <h5 class="offcanvas-title" id="offcanvasWithBothOptionsLabel">Menu</h5>
            <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
          </div>
          <div class="offcanvas-body">
            <button type="button" class="btn btn-outline-danger w-100" @click="logoutUser">Logout</button>
          </div>
        </div>

        <div class="list-group list-group-flush overflow-auto flex-grow-1">
          <button 
            v-for="chat in chats" 
            :key="chat.id"
            @click="selectChat(chat)"
            class="list-group-item list-group-item-action py-3 border-0"
            :class="{ 'active-chat': selectedChat && selectedChat.id === chat.id }"
          >
            <div class="d-flex align-items-center">
              <div class="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center flex-shrink-0" style="width: 45px; height: 45px;">
                {{ chat.name.charAt(0) }}
              </div>
              <div class="ms-3 overflow-hidden">
                <div class="d-flex justify-content-between align-items-center">
                  <strong class="text-truncate">{{ chat.name }}</strong>
                  <img 
                    v-if="chat.cyphered" 
                    src="/lock.svg" 
                    alt="Cifrata" 
                    class="ms-2" 
                    style="width: 16px; height: 16px;"
                  >
                  <img 
                    v-else 
                    src="/unlock.svg" 
                    alt="Non cifrata" 
                    class="ms-2" 
                    style="width: 16px; height: 16px;"
                  >
                </div>
                <div class="small text-muted text-truncate">{{ chat.last_msg }}</div>
              </div>
            </div>
          </button>
        </div>
      </div>

      <div class="col-md-8 col-lg-9 p-0 d-flex flex-column h-100 bg-white">
        <div v-if="selectedChat" class="d-flex flex-column h-100">
          <div class="p-3 border-bottom d-flex align-items-center justify-content-between bg-light">
            <strong>{{ selectedChat.name }}</strong>
            <button @click="sendkey()" class="btn btn-primary btn-sm">Invia chiave</button>
          </div>
          
          <div class="messages-area flex-grow-1">
          <div ref="messagesContainer" class="messages-scroll p-3 bg-chat" @scroll="handleMessagesScroll">
             <div 
               v-for="m in messaggi" 
               :key="m.id" 
               class="message-wrapper"
               :class="{ 'message-out': m.out, 'message-in': !m.out, 'message-system': !!m.chiave, 'message-system-type': !!m.system_type}"
               @contextmenu.prevent="openMessageMenu($event, m)"
               @touchstart="handleMessageTouchStart($event, m)"
               @touchmove="handleMessageTouchMove($event)"
               @touchend="handleMessageTouchEnd"
               @touchcancel="handleMessageTouchEnd"
             >
               <div 
                 class="message-bubble"
                 :class="{
                   'message-error': m.error,
                   'message-pending': m.pending,
                   'message-system-bubble': !!m.chiave,
                   'message-system-type-bubble': !!m.system_type
                 }"
               >
                 <template v-if="m.system_type">
                   <div class="message-system-content">
                     <span class="message-system-label">{{ m.system_type }}</span>
                   </div>
                 </template>
                 <template v-else>
                   <div v-if="!m.chiave" class="message-header">
                   <span class="message-sender">
                     {{ m.out ? 'Tu' : (m.sender_username || m.sender_id) }}
                   </span>
                   <img
                     v-if="m.secure"
                     src="/lock.svg"
                     alt="Cifrato"
                     class="message-secure-icon"
                   >
                 </div>
                 <div v-if="m.file">
                   <!-- Documenti -->
                   <div v-if="m.media_type === 'document'" class="file-container" @click="handleFileClick(m)">
                     <img src="/file.svg" alt="file" class="file-icon">
                     <div class="file-info">
                       <div class="file-name">{{ m.filename }}</div>
                       <div class="file-size">{{ formatFileSize(m.size) }}</div>
                     </div>
                   </div>
                   
                   <!-- Immagini -->
                   <div v-else-if="m.media_type === 'photo'" class="media-container">
                     <img :src="mediaUrl(m.id, m.chat_id)" alt="photo" class="media-image" style="max-width: 100%; max-height: 300px; border-radius: 8px;">
                     <div class="file-size" v-if="m.size">{{ formatFileSize(m.size) }}</div>
                   </div>
                   
                   <!-- Video -->
                   <div v-else-if="m.media_type === 'video'" class="media-container">
                     <video controls style="max-width: 100%; max-height: 300px; border-radius: 8px;">
                       <source :src="mediaUrl(m.id, m.chat_id)" :type="m.mime || 'video/mp4'">
                       Errore: browser non supporta video
                     </video>
                     <div class="file-size" v-if="m.size">{{ formatFileSize(m.size) }}</div>
                   </div>
                   
                   <!-- Sticker statici -->
                   <div v-else-if="m.media_type === 'sticker'" class="media-container">
                     <img :src="mediaUrl(m.id, m.chat_id)" alt="sticker" class="sticker-icon" style="width: 150px; height: 150px;">
                   </div>
                   
                   <!-- Sticker animati -->
                   <div v-else-if="m.media_type === 'sticker_animated'" class="media-container">
                     <video v-if="m.mime && m.mime.startsWith('video/')" autoplay loop muted playsinline style="width: 150px; height: 150px; border-radius: 8px;">
                       <source :src="mediaUrl(m.id, m.chat_id)" :type="m.mime">
                     </video>
                     <div
                       v-else
                       class="sticker-anim-container"
                       style="width: 150px; height: 150px;"
                       :ref="(el) => setAnimatedStickerRef(m.id, el)"
                     ></div>
                   </div>
                   
                   <!-- GIF -->
                   <div v-else-if="m.media_type === 'gif'" class="media-container">
                     <video autoplay loop muted playsinline style="max-width: 100%; max-height: 300px; border-radius: 8px;">
                       <source :src="mediaUrl(m.id, m.chat_id)" type="video/mp4">
                     </video>
                     <div class="file-size" v-if="m.size">{{ formatFileSize(m.size) }}</div>
                   </div>
                 </div>
                 <div class="message-text" v-if="!m.error">
                    <template v-if="m.chiave">
                      <div class="message-system-content">
                        <img src="/key.svg" alt="Chiave" class="message-key-icon">
                        <span class="message-system-key">{{ m.chiave }}</span>
                      </div>
                    </template>
                    <template v-else>
                      {{ m.text }}
                    </template>
                  </div>
                  <div class="message-text" v-else>
                      {{m.error}}<img 
                    src="/alert-triangle.svg"  
                    alt="Invia"
                    class="send-icon"
                  >
                  </div>
                 <div class="message-time">
                   {{ m.pending ? 'in invio...' : new Date(m.date).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) }}
                 </div>
                 </template>
               </div> 
             </div>
             <div v-if="contextMenuVisible" class="message-context-backdrop" @click="closeMessageMenu"></div>
             <div
               v-if="contextMenuVisible"
               ref="messageContextMenu"
               class="message-context-menu"
               :style="{ top: contextMenuPos.y + 'px', left: contextMenuPos.x + 'px' }"
               @click.stop
             >
               <button type="button" class="message-context-item" @click="handleMessageAction('reply')">Rispondi</button>
               <button type="button" class="message-context-item" @click="handleMessageAction('edit')">Modifica</button>
               <button type="button" class="message-context-item" @click="handleMessageAction('pin')">Pin</button>
               <button type="button" class="message-context-item danger" @click="handleMessageAction('delete')">Elimina</button>
             </div>
          </div>
          <button
            type="button"
            class="btn btn-primary chat-overlay-btn"
            @click="scrollToBottom"
            v-show="dist"
          >
            <img 
                    src="/arrow-down.svg"  
                    alt="Invia"
                    class="send-icon"
                  >
          </button>
          </div>

            <form @submit.prevent="handleSubmit()">
              <div class="p-3 border-top d-flex align-items-center gap-2">
                <input
                  ref="messageInput"
                  v-model="text"
                  type="text"
                  class="form-control"
                  :disabled="sendingMessage || sendingEncryptedFile"
                  placeholder="Scrivi un messaggio..."
                >
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" id="altSend" v-model="useAltSend" :disabled="sendingMessage || sendingEncryptedFile">
                  <label class="form-check-label" for="altSend">cifra</label>
                </div>
                <button type="submit" class="btn btn-primary send-btn" v-if="!file || text.length < 1024" :disabled="sendingMessage || sendingEncryptedFile">
                  <img 
                    src="/send.svg"  
                    alt="Invia"
                    class="send-icon"
                  >
                </button>
                <div v-else-if="file && text.length >= 1024" class="d-flex align-items-center gap-2">
                  <button type="button" class="btn btn-secondary send-btn" disabled title="Messaggio troppo lungo">
                    <img 
                      src="/send.svg"  
                      alt="Messaggio troppo lungo"
                      class="send-icon"
                      style="opacity: 0.5"
                    >
                  </button>
                  <small class="text-danger">Messaggio troppo lungo ({{ text.length }}/1024)</small>
                </div>
                <input
                  ref="fileInput" 
                  type="file"
                  style="display: none"
                  :disabled="sendingMessage || sendingEncryptedFile"
                  @change="handleFileChange"
                />
                <button type="button" class="btn btn-primary send-btn" :disabled="sendingMessage || sendingEncryptedFile" @click="$refs.fileInput.click()">
                  <img src="/paperclip.svg" alt="Allega" class="send-icon" />
                </button>
                <button v-if="file" type="button" class="btn btn-danger" :disabled="sendingMessage || sendingEncryptedFile" @click="removeFile">
                  Rimuovi file
                </button>
              </div>  
              <div v-if="sendingEncryptedFile" class="px-3 pb-2 text-muted small">
                Invio file cifrato in corso...
              </div>
              <div v-if="downloadingFile" class="px-3 pb-2 text-muted small">
                Scaricamento file in corso{{ downloadingFileName ? `: ${downloadingFileName}` : '' }}...
              </div>
            </form>
        </div>

        <div v-else class="btn btn-primary h-100 d-flex align-items-center justify-content-center bg-light text-muted">
          Seleziona una chat per iniziare a messaggiare
        </div>
      </div>

    </div>
  </div>
</template>

<style scoped>
/* Messaggi con system_type centrati e colorati */
.message-wrapper.message-system-type {
  justify-content: center !important;
  align-items: center;
}

.message-system-type-bubble {
  max-width: 60%;
  background-color: #ffe9b3;
  color: #7a4c00;
  border: 2px solid #ffd166;
  border-radius: 24px;
  box-shadow: 0 2px 8px rgba(255, 209, 102, 0.15);
  margin: 0 auto;
  font-weight: 600;
}
.vh-100 { height: 100vh; overflow: hidden; }


.active-chat {
  background-color: #e9ecef ; 
  border-left: 4px solid #198754 ; 
}


.bg-chat {
  background-color: #f8f9fa;
  position: relative;
}

.messages-area {
  position: relative;
  flex: 1 1 auto;
  min-height: 0;
}

.messages-scroll {
  height: 100%;
  overflow: auto;
}

.chat-overlay-btn {
  position: absolute;
  right: 16px;
  bottom: 16px;
  z-index: 5;
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.2);
}

.message-context-backdrop {
  position: fixed;
  inset: 0;
  z-index: 20;
}

.message-context-menu {
  position: fixed;
  z-index: 21;
  min-width: 160px;
  padding: 6px;
  background-color: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  box-shadow: 0 10px 24px rgba(0, 0, 0, 0.15);
}

.message-context-item {
  width: 100%;
  border: 0;
  background: transparent;
  text-align: left;
  padding: 8px 10px;
  border-radius: 8px;
  font-size: 0.9rem;
  color: #111827;
}

.message-context-item:hover {
  background-color: #f3f4f6;
}

.message-context-item.danger {
  color: #b91c1c;
}

.message-wrapper {
  display: flex;
  margin-bottom: 12px;
}

.message-wrapper.message-out {
  justify-content: flex-end;
}

.message-wrapper.message-in {
  justify-content: flex-start;
}

.message-bubble {
  max-width: 70%;
  padding: 10px 14px;
  border-radius: 18px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  word-wrap: break-word;
}

.message-system-bubble {
  max-width: 90%;
  background-color: #f3f4f6;
  color: #374151;
  border: 1px dashed #d1d5db;
  border-radius: 999px;
  box-shadow: none;
}

.message-header {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
  font-size: 0.85rem;
  margin-bottom: 4px;
  color: #7c3aed; 
}

.message-secure-icon {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
}

.message-key-icon {
  width: 14px;
  height: 14px;
  margin-right: 6px;
  vertical-align: middle;
  filter: grayscale(1) brightness(0.6);
}

.message-system-content {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: center;
}

.message-system-label {
  font-size: 0.7rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: #6b7280;
  font-weight: 600;
}

.message-system-key {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 6px;
  background-color: #ffffff;
  border: 1px solid #e5e7eb;
  color: #111827;
  font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
  font-size: 0.85rem;
}

.message-out .message-bubble {
  background-color: #0b93f6;
  color: white;
  border-bottom-right-radius: 4px;
}

.message-out .message-header {
  color: #e9d5ff; 
}

.message-in .message-bubble {
  background-color: #e5e5ea;
  color: #000;
  border-bottom-left-radius: 4px;
}

.message-in .message-header {
  color: #6d28d9; 
}

.message-text {
  margin-bottom: 4px;
  line-height: 1.4;
}

.message-bubble.message-error {
  background-color: #fee2e2;
  border: 1px solid #fecaca;
  color: #7f1d1d;
}

.message-error .message-text {
  color: #7f1d1d;
}

.message-error .message-time {
  color: #7f1d1d;
  opacity: 0.6;
}

.message-time {
  font-size: 0.75rem;
  opacity: 0.7;
  text-align: right;
}

.message-bubble.message-pending {
  opacity: 0.72;
}


.overflow-auto::-webkit-scrollbar {
  width: 5px;
}
.overflow-auto::-webkit-scrollbar-thumb {
  background: #ccc;
  border-radius: 10px;
}

/* Bottone invio quadrato e icona centrata */
.send-btn {
  width: 40px;
  height: 40px;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
}
.send-icon {
  width: 22px;
  height: 22px;
  display: block;
  margin: auto;
}

/* File display */
.file-container {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px;
  background-color: rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  margin-bottom: 6px;
}

.file-icon {
  width: 40px;
  height: 40px;
  flex-shrink: 0;
}

.file-info {
  flex-grow: 1;
  min-width: 0;
}

.file-name {
  font-weight: 600;
  font-size: 0.9rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-size {
  font-size: 0.75rem;
  opacity: 0.8;
  margin-top: 2px;
}



</style>