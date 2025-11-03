import React, { useState } from 'react';
import { login } from '../api/authApi'; 
// 1. IMPORT HOOK ĐIỀU HƯỚNG
import { useNavigate } from 'react-router-dom'; 

function LoginPage() {
  // 2. KHỞI TẠO HOOK
  const navigate = useNavigate(); 
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setSuccessMessage('');

    try {
      // 3. Gọi hàm login
      const data = await login(email, password);

      // 4. Lưu token vào localStorage
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      
      setSuccessMessage('Đăng nhập thành công! Đang chuyển hướng...');

      // 5. Đợi 1 giây rồi chuyển trang
      setTimeout(() => {
        navigate('/dashboard'); // <-- LỆNH CHUYỂN TRANG
      }, 1000); 

    } catch (err) {
      // 6. Bắt lỗi (ví dụ: "Sai mật khẩu")
      setError(err.message);
    }
  };

  return (
    <div style={{ padding: '20px', maxWidth: '400px', margin: 'auto' }}>
      <h2>Đăng nhập</h2>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '10px' }}>
          <label>Email (username): </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{ width: '100%' }}
          />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Password: </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ width: '100%' }}
          />
        </div>
        <button type="submit">Đăng nhập</button>
      </form>

      {/* Hiển thị thông báo */}
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {successMessage && <p style={{ color: 'green' }}>{successMessage}</p>}
    </div>
  );
}

export default LoginPage;