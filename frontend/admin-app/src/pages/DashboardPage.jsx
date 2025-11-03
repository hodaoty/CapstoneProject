import React from 'react';
import { Link } from 'react-router-dom'; // Import Link để điều hướng

function DashboardPage() {
  const token = localStorage.getItem('access_token');

  return (
    <div style={{ padding: '20px' }}>
      <h2>Chào mừng bạn đến Trang Quản Trị</h2>
      
      {token ? (
        <p style={{ color: 'green' }}>Bạn đã đăng nhập thành công!</p>
      ) : (
        <p style={{ color: 'red' }}>Bạn chưa đăng nhập.</p>
      )}

      <nav>
        <ul>
          <li>
            {/* Tạo link để đi đến trang User List */}
            <Link to="/users">Quản lý Người dùng</Link>
          </li>
          {/* (Bạn có thể thêm link đến trang Quản lý Sản phẩm sau) */}
        </ul>
      </nav>
    </div>
  );
}

export default DashboardPage;