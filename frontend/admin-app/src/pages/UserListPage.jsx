import React, { useState, useEffect } from 'react';
import { getUsers } from '../api/userApi'; // Import hàm API

function UserListPage() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // 1. Dùng useEffect để gọi API khi trang được tải
  useEffect(() => {
    const fetchUsers = async () => {
      setIsLoading(true);
      setError('');
      try {
        const data = await getUsers();
        setUsers(data);
      } catch (err) {
        setError(err.message);
        // Nếu lỗi (vd: 401 token hết hạn), xóa token và bắt đăng nhập lại
        if (err.message.includes('401') || err.message.includes('token')) {
          localStorage.removeItem('access_token');
          // Có thể thêm: window.location.href = '/login';
        }
      } finally {
        setIsLoading(false);
      }
    };

    fetchUsers();
  }, []); // Mảng rỗng [] nghĩa là chỉ chạy 1 lần khi component mount

  // 2. Render giao diện
  if (isLoading) {
    return <div style={{ padding: '20px' }}>Đang tải dữ liệu...</div>;
  }

  if (error) {
    return <div style={{ padding: '20px', color: 'red' }}>Lỗi: {error}</div>;
  }

  return (
    <div style={{ padding: '20px' }}>
      <h2>Danh sách User</h2>
      <table border="1" style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={{ padding: '8px' }}>ID</th>
            <th style={{ padding: '8px' }}>Email</th>
            <th style={{ padding: '8px' }}>Trạng thái</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td style={{ padding: '8px' }}>{user.id}</td>
              <td style={{ padding: '8px' }}>{user.email}</td>
              <td style={{ padding: '8px' }}>{user.is_active ? 'Hoạt động' : 'Khóa'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default UserListPage;