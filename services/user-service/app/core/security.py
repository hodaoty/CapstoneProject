from passlib.context import CryptContext

# Sử dụng thuật toán bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verrify_password(plain_password, hashed_password):
    """Kiểm tra mật khẩu thô có khớp với mật khẩu đã băm không"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """Băm mật khẩu"""
    return pwd_context.hash(password)
