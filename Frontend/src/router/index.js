import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Sign from '../views/Signup.vue'
import Home from '../views/Home.vue'
import api from '../services/api'
import Guide from '../views/Guide.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'login',
      component: Login,
    },
    {
      path: '/signup',
      name: 'signup',
      component: Sign
    },
    {
      path:'/home',
      name: 'home',
      component: Home,
      meta: { requiresAuth: true }
    },
    {
      path:'/chat/:id',
      name: 'chat',
      component: Home,
      meta: { requiresAuth: true }
    },
    {
      path:'/guide',
      name: 'guide',
      component: Guide,
    }
  ],
})

router.beforeEach(async (to) => {
  if (!to.meta?.requiresAuth) {
    return true
  }

  try {
    await api.get('/login/check')
    return true
  } catch (e) {
    return { name: 'login' }
  }
})

export default router
