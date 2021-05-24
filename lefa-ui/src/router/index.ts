import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router'
import { ElMessage } from 'element-plus'
// import HelloWorld from '@/components/HelloWorld.vue'
// import Home from '@/views/home.vue'
// import Login from '@/views/login/index.vue'

const routes: Array<RouteRecordRaw> = [
  {
    path: '/',
    name: 'Home',
    component: () => import('@/components/HelloWorld.vue')
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/login/index.vue')
  },
  {
    path: '/permission',
    name: 'Permission',
    component: () => import('@/views/permission.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

const isLogin = function () {
  let login = localStorage.getItem('WEB_TOKEN')
  return !!login
}

router.beforeEach(async (to, from, next) => {
  if (to.name !== 'Login' && !isLogin()) next({ name: 'Login' })
  // 未登录直接访问message有bug，待改进
  else next()
})

export default router
