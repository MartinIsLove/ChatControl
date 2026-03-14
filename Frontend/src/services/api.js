import axios from 'axios'

const instance = axios.create({ 
  baseURL: __API_URL__,
  httpsAgent: { rejectUnauthorized: false },
  withCredentials: true
})

export default instance
