import axios from './axios'

export const login = (data: Object) => {
  return axios.post('/hzyText', {
    data: data
  })
}

export const getUserInfo = () => {
  return axios.post('/getUserInfo')
}
