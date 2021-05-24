import { createStore } from 'vuex'
import { storages } from './storage'

const defaultState = {
  user: [],
  token: storages.getLocalStorageName || ''
}

export default createStore({
  state() {
    return defaultState
  },
  mutations: {
    login(state: typeof defaultState, token) {
      state.token = token
      storages.setLocalStorageName = token
    },
    userInfo(state: typeof defaultState, user) {
      // 直接修改？
      // const newState = JSON.parse(JSON.stringify(state))
      state.user = user.data
    }
  },
  actions: {},
  getters: {}
})
