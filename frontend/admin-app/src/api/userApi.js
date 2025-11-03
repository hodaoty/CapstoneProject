import apiClient from './apiClient';

/**
 * Lấy danh sách tất cả user (Yêu cầu có token)
 * @returns {Promise<Array>} Danh sách user
 */
export const getUsers = async () => {
  // 1. Lấy token đã lưu
  const token = localStorage.getItem('access_token');
  if (!token) {
    throw new Error('Bạn chưa đăng nhập');
  }

  try {
    // 2. Gọi API với Authorization header
    const response = await apiClient.get('/users/', {
      headers: {
        Authorization: `Bearer ${token}`, // <-- Gửi token ở đây
      },
    });
    return response.data; // Trả về mảng user
    
  } catch (err) {
    if (err.response) {
      // Nếu token hết hạn hoặc không hợp lệ, API sẽ trả về lỗi 401 hoặc 403
      throw new Error(err.response.data.detail || 'Không thể lấy dữ liệu');
    }
    throw new Error('Không thể kết nối đến máy chủ');
  }
};