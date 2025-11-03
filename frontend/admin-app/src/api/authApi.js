import apiClient from './apiClient';

/**
 * Gọi API đăng nhập
 * @param {string} username (chính là email)
 * @param {string} password 
 * @returns {Promise<object>} Dữ liệu token (access_token, refresh_token)
 */
export const login = async (username, password) => {
  // 1. Chuẩn bị dữ liệu cho 'x-www-form-urlencoded'
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);

  try {
    // 2. Gọi API login
    const response = await apiClient.post(
      '/auth/login', // Chỉ cần đường dẫn con, vì baseURL đã có trong apiClient
      formData,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );
    
    // 3. Trả về dữ liệu nếu thành công
    return response.data;
    
  } catch (err) {
    // 4. Ném lỗi ra ngoài để component UI (LoginPage) có thể bắt và hiển thị
    if (err.response && err.response.data) {
      throw new Error(err.response.data.detail || 'Lỗi đăng nhập');
    }
    throw new Error('Không thể kết nối đến máy chủ');
  }
};