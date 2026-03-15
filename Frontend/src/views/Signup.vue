<script>
import api from '@/services/api'

export default {
    data: function() {
        return {
            errormsg: null,
            loading: false,
            phase: false,
            phase_sign: 0,
            username: '',
            api_id: '',
            api_hash: '',
            phone_prefix: '+39',
            phone: '',
            passphrase: '',
            sms_code: '',
            password: '',
        }
    },
    methods: {
        isPassphraseValid() {
            return /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(this.passphrase)
        },
        nextPhase() {
            this.errormsg = null
            const apiHashOk = /^[a-f0-9]{32}$/.test(this.api_hash)
            if (!this.api_id || !this.api_hash || !apiHashOk) {
                this.errormsg = 'Inserisci API ID e API hash validi per continuare.'
                return
            }
            this.phase = true
        },
        async submitForm() {
            this.errormsg = null
            if (!this.isPassphraseValid()) {
                this.errormsg = 'La passphrase deve avere almeno 8 caratteri, una maiuscola, un numero e un carattere speciale.'
                return
            }
            this.loading = true
            let response
            try {
                const phoneSanitized = this.phone.replace(/\s+/g, '')
                response = await api.post('/signup/step1', {
                    api_id: this.api_id,
                    api_hash: this.api_hash,
                    phone: `${this.phone_prefix}${phoneSanitized}`,
                    username: this.username,
                    password: this.passphrase
                })
            } catch (e) {
                this.errormsg = e.response?.data?.message || e.message
            } finally {
                this.loading = false
                if (response?.data) {
                    this.phase_sign = 1
                }
            }
        },
        async submitAll() {
            this.errormsg = null
            this.loading = true
            let response
            try {
                response = await api.post('/signup/step2', {
                    sms_code: this.sms_code,
                }, { withCredentials: true })
            } catch (e) {
                this.errormsg = e.response?.data?.message || e.message
            } finally {
                this.loading = false
                if (response?.data?.status === 'need_2fa_password') {
                    this.phase_sign = 2
                } else if (response?.data?.status === 'Account creato!') {
                    this.$router.push('/home')
                }
            }
        },
        async submitPass() {
            this.errormsg = null
            this.loading = true
            let response
            try {
                response = await api.post('/signup/step3', {
                    password: this.password,
                }, { withCredentials: true })
            } catch (e) {
                this.errormsg = e.response?.data?.message || e.message
            } finally {
                this.loading = false
                if (response?.data?.status === 'Account creato!') {
                    this.$router.push('/home')
                }
            }
        },
    },
}
</script>
<template>
    <div class="signup-page">
        <div class="signup-card">
            <div class="signup-top">
                <button type="button" class="btn btn-link p-0" @click="$router.push('/')">
                     <- Torna al login
                </button>
                <RouterLink class="btn btn-link p-0" to="/guide">
                    Guida per API Telegram
                </RouterLink>
            </div>
            <form @submit.prevent="phase ? submitForm() : nextPhase()">
                <div v-show="!phase && phase_sign === 0">
                    <div class="mb-3">
                        <label for="exampleInputEmail1" class="form-label">API ID</label>
                        <input type="text" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="api_id">
                    </div>
                    <div class="mb-3">
                        <label for="exampleInputPassword1" class="form-label">API hash</label>
                        <input type="text" class="form-control" id="exampleInputPassword1" v-model="api_hash">
                    </div>
                    <p v-if="api_hash && !/^[a-f0-9]{32}$/.test(api_hash)" class="text-danger">
                        API hash non valido (32 caratteri hex minuscoli).
                    </p>
                    <p v-else-if="(api_id || api_hash) && (!api_id || !api_hash)" class="text-danger">
                        Inserisci API ID e API hash per continuare.
                    </p>
                    <p v-if="errormsg" class="text-danger">{{ errormsg }}</p>
                    <button type="submit" class="btn btn-primary w-100" :disabled="!api_id || !api_hash || !/^[a-f0-9]{32}$/.test(api_hash)">Avanti</button>
                </div>

                <div v-show="phase && phase_sign === 0">
                    <div class="mb-3">
                        <label for="exampleInputPassword1" class="form-label">Telefono</label>
                        <div class="input-group">
                            <select class="form-select" v-model="phone_prefix" aria-label="prefisso telefonico">
                                <option value="+39">+39 Italia</option>
                                <option value="+20">+20 Egitto</option>
                                <option value="+66">+66 Thailandia</option>
                                <option value="+44">+44 Regno Unito</option>
                                <option value="+49">+49 Germania</option>
                                <option value="+33">+33 Francia</option>
                                <option value="+34">+34 Spagna</option>
                                <option value="+1">+1 USA</option>
                                <option value="+41">+41 Svizzera</option>
                            </select>
                            <input type="tel" class="form-control" id="exampleInputPassword1" v-model="phone" placeholder="Numero senza prefisso">
                        </div>
                        <p v-if="phone && !/^[0-9]{6,12}$/.test(phone)" class="text-danger mt-2">
                            Inserisci solo numeri, 6-12 cifre.
                        </p>
                    </div>
                    <div class="mb-3">
                        <label for="exampleInputPassword1" class="form-label">Username</label>
                        <input type="text" class="form-control" id="exampleInputPassword1" v-model="username">
                    </div>
                    <div class="mb-3">
                        <label for="exampleInputPassword1" class="form-label">Passphrase</label>
                        <input type="password" class="form-control" id="exampleInputPassword1" v-model="passphrase">
                        <p v-if="passphrase && !isPassphraseValid()" class="text-danger mt-2">
                            Minimo 8 caratteri, almeno una maiuscola, un numero e un carattere speciale.
                        </p>
                    </div>
                    <p v-if="errormsg" class="text-danger">{{ errormsg }}</p>
                    <div class="d-flex gap-2">
                        <button type="button" class="btn btn-secondary flex-grow-1" @click="phase = false">Indietro</button>
                        <button type="submit" class="btn btn-primary flex-grow-1" :disabled="loading || !phone || !/^[0-9]{6,12}$/.test(phone) || !username || !isPassphraseValid()">
                            {{ loading ? 'Attendi...' : 'Continua' }}
                        </button>
                    </div>
                </div>
            </form>
            <form @submit.prevent="submitAll()">
                <div v-show="phase_sign === 1">
                    <div class="mb-3">
                        <label for="exampleInputEmail1" class="form-label">Inserisci il codice SMS ricevuto</label>
                        <input type="text" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="sms_code">
                    </div>
                    <p v-if="sms_code && !/^[0-9]+$/.test(sms_code)" class="text-danger">
                        Inserisci solo numeri nel codice SMS.
                    </p>
                    <button type="submit" class="btn btn-primary w-100" :disabled="!sms_code || !/^[0-9]+$/.test(sms_code)">Registrati</button>
                </div>
            </form>
            <form @submit.prevent="submitPass()">
                <div v-show="phase_sign === 2">
                    <div class="mb-3">
                        <label for="exampleInputEmail1" class="form-label">Inserisci la password del tuo account Telegram</label>
                        <input type="password" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="password">
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Registrati</button>
                </div>
            </form>
        </div>
    </div>
</template>

<style scoped>
.signup-page {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px 16px;
}

.signup-card {
    width: 100%;
    max-width: 520px;
    padding: 24px;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    background: #ffffff;
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.08);
}

.signup-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 16px;
}
</style>