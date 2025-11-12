async function registerUser(event) {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('error');

    try {
        const user = await apiPost(`${API_USER_URL}/users/`, { email, password });
        alert('Registration successful! Please login.');
        window.location.href = 'login.html';
    } catch (error) {
        errorDiv.textContent = error.message || 'Registration failed.';
    }
}

async function loginUser(event) {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('error');

    try {
        // Giả định auth-service có endpoint /auth/login trả {access_token}
        const data = await apiPost(`${API_AUTH_URL}/auth/login`, { email, password });
        localStorage.setItem('token', data.access_token);
        window.location.href = 'dashboard.html';
    } catch (error) {
        errorDiv.textContent = error.message || 'Login failed.';
    }
}

async function fetchUserInfo() {
    try {
        // Giả định GET /users/me hoặc dùng email từ token
        const user = await apiGet(`${API_USER_URL}/users/me`); // Thêm endpoint này nếu cần
        document.getElementById('userEmail').textContent = `Email: ${user.email}`;
    } catch (error) {
        logoutUser();
    }
}

function logoutUser() {
    localStorage.removeItem('token');
    window.location.href = 'login.html';
}