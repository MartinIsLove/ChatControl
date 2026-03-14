<script>
    import api from '@/services/api'
     export default {
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                sms: '',
                expired: 0,
                username: '',
                password: '',
                pass: '',
            }
        },
        methods: {
            async login(){
                this.errormsg = null
                this.loading = true
                let response
                try {
                    response = await api.post('/login', {
                        username: this.username,
                        password: this.password,
                    }, { withCredentials: true })
                    console.log('Signup OK:', response.data)
                } catch (e) {
                    this.errormsg = e.response?.data?.message || e.message
                } finally {
                    this.loading = false
                    console.log('Response status:', response?.data?.status)
                    if (response?.data?.status == "logged in"){
                        this.$router.push('/home')
                    }
                    else if(response?.data?.status == "session expired"){
                        this.expired = 1
                    }
                }
            },
            async login_expired(){
                this.errormsg = null
                this.loading = true
                let response
                try {
                    response = await api.post('/login/expired', {
                        sms: this.sms,
                        password: this.pass
                    }, { withCredentials: true })
                    console.log('Signup OK:', response.data)
                } catch (e) {
                    this.errormsg = e.response?.data?.message || e.message
                } finally {
                    this.loading = false
                    this.sms = ''
                    this.pass = ''
                    console.log('Response status:', response?.data?.status)
                    if (response?.data?.status == "logged in"){
                        this.$router.push('/home')
                    }
                    else{
                        this.expired = 0
                    }
                }
            }
        },
        mounted() {
            // this.refresh()
	    }
    }
</script>
<template>
    <div class="login-page">
        <div class="login-card">
            <form v-if="expired == 0" @submit.prevent="login()">
                <div>
                    <div class="mb-3">
                        <label for="exampleInputEmail1" class="form-label">Username</label>
                        <input type="text" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="username">
                    </div>
                    <div class="mb-3">
                        <label for="exampleInputPassword1" class="form-label">Password</label>
                        <input type="password" class="form-control" id="exampleInputPassword1" v-model="password">
                    </div>
                </div>

                <button type="submit" class="btn btn-primary w-100">{{loading ? 'attendi...' : 'submit' }}</button>
                <div>
                    <p class="mt-3 text-center">
                        Non hai un account?
                        <RouterLink to="/signup">Registrati</RouterLink>
                    </p>
                </div>
            </form>

            <form v-else @submit.prevent="login_expired()">
                <div>
                    <div class="mb-3">
                        <label for="exampleInputEmail1" class="form-label">SMS</label>
                        <input type="text" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="sms">

                        <label for="exampleInputEmail1" class="form-label">Password di Telegram</label>
                        <input type="password" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="pass">
                    </div>
                    <button type="submit" class="btn btn-primary w-100">{{loading ? 'attendi...' : 'submit' }}</button>
                </div>
            </form>
            <p v-if="errormsg" class="text-danger mt-3 mb-0">{{ errormsg }}</p>
        </div>
    </div>
</template>

<style scoped>
.login-page {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px 16px;
}

.login-card {
    width: 100%;
    max-width: 420px;
    padding: 24px;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    background: #ffffff;
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.08);
}
</style>