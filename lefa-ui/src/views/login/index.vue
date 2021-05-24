<template>
  <div class="body">
    <div class="login">
      <div class="mask"></div>
      <el-card class="box-card">
        <el-form :rules="rules"
                 :inline="true"
                 :model="formInline"
                 ref="formInline"
                 class="demo-form-inline">
          <h3 class="title">板蓝根的后花园</h3>
          <el-form-item prop="username">
            <el-input class="input"
                      v-model="formInline.username"
                      placeholder="账号"></el-input>
          </el-form-item>
          <el-form-item prop="password">
            <el-input class="input"
                      placeholder="密码"
                      v-model="formInline.password"
                      show-password></el-input>
          </el-form-item>
          <el-button @click="submitForm('formInline')"
                     class="button"
                     type="primary">登录</el-button>
        </el-form>
      </el-card>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue'
import { ElMessage } from 'element-plus'
import { login, getUserInfo } from '../../utils/api'
// import axios from 'axios'

export default defineComponent({
  name: 'Login',
  setup() {
    return {}
  },
  data() {
    return {
      formInline: {
        username: '',
        password: ''
      },
      rules: {
        username: [{ required: true, message: '账号不能为空', trigger: 'blur' }],
        password: [{ required: true, message: '密码不能为空', trigger: 'blur' }]
      }
    }
  },
  methods: {
    async submitForm(formName: Object) {
      this.$refs[formName].validate((valid: Boolean) => {
        if (valid) {
          // 不优雅
          const Login = async () => {
            const msg = await login(this.formInline)
            if (msg.data.code === 200) {
              ElMessage.success({
                message: '登录成功！',
                type: 'success'
              })
              this.$store.commit('login', msg.data.token)
              this.$store.commit('userInfo', await getUserInfo())
              this.$router.push('/')
            } else {
              ElMessage.error('账号或密码错误！')
            }
          }
          Login()
        } else {
          return false
        }
      })
    }
  }
})
</script>

<style scoped>
.body {
  background-image: url('../../assets/123.png');
  background-size: cover;
  height: 100vh;
  z-index: 1;
}
/* .body:after {
  content: '';
  width: 100%;
  height: 100%;
  position: absolute;
  left: 0;
  top: 0;
  background: inherit;
  filter: blur(1.2px);
  z-index: 2;
} */
.login {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100%;
  z-index: 11;
}
.login > * {
  z-index: 11;
}

.title {
  margin: 0px auto 30px auto;
  text-align: center;
  color: #00f134;
}
.box-card {
  padding: 20px;
  width: 350px;
}
.input {
  width: 310px;
}
.button {
  width: 310px;
}
</style>
