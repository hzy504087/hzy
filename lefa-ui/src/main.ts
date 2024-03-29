import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/lib/theme-chalk/index.css'
import App from './App.vue'
import router from './router'
import stroe from './store'

const app = createApp(App)
app.use(ElementPlus)
app.use(router)
app.use(stroe)
app.mount('#app')
