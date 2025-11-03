import axios from 'axios';

// Tạo một instance của axios
const apiClient = axios.create({
  // URL của API Gateway
  baseURL: 'http://localhost/api', 
  timeout: 10000, // Thời gian chờ 10s
});

export default apiClient;