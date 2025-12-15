from nicegui import ui, app
import httpx
import os 
from jose import jwt

API_BASE_URL= os.environ.get("API_GATEWAY_URL","http://api-gateway:80")
#--Decode ROLE--#
def get_user_role(token):
    try:
        payload = jwt.get_unverified_claims(token)
        return payload.get('role', "USER")
    except Exception:
        return None
#API
    
async def login_api(username, password):
    try:
        async with httpx.AsyncClient() as client:
            respone = await client.post(
                f"{API_BASE_URL}/api/auth/login",
                data={"username": username, "password": password},
                timeout=0.5
            )
            if respone.status_code==200:
                return respone.json() #send back access token
            return None
    except Exception as e:
        print(f"Login Error: {e}")
        return None
    
async def get_users_api(token):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            respone = await client.get(
                f"{API_BASE_URL}/api/users/",
                headers=headers,
                timeout=5.0
            )
            if respone.status_code==200:
                return respone.json()
            return []
    except Exception:
        return []

#def register
async def register_user_api(email, password):
    try:
        async with httpx.AsyncClient() as client:
            respone = await client.post(
                f"{API_BASE_URL}/api/users/",
                json={"email": email, "password": password, "role": "USER"},
                timeout=0.5
            )
            if respone.status_code==200:
                return True, respone.json()
            else:
                error_detail=respone.json().get("detail", "Loi khong xac dinh")
                return False, error_detail
    except Exception as e:
        print(f"Register Error :{e}")
        return False, str(e)
#UI
#--PROFILE PAGE--#
@ui.page('/profile')
def profile_page():
    token = app.storage.user.get('token')
    if not token:
        ui.navigate.to('/')
        return
    
    #Check role
    role = get_user_role(token)

    def logout():
        app.storage.user['token'] = None
        ui.notify('Log out', type='info')
        ui.navigate.to('/')

    with ui.card().classes('absolute-center w-96 p-6 items-center'):
        ui.icon('person', size='48px').classes('text-blue-500 mb-4')
        ui.label(f'Hello , {role}!').classes('text-xl font-bold')
        ui.label(f'This is an area for USER/STAFF').classes('text-gray-500 text-center')

        if role == 'ADMIN':
            ui.button('ADMIN PAGE',on_click=lambda:ui.navigate.to('/dashboard')).classes('mt-4 w-full bg-purple-600')
        
        ui.button('Log out', on_click=logout).classes('mt-4 w-full bg-red-500')

# --- TRANG DASHBOARD (CHỈ CHO ADMIN) ---
@ui.page('/dashboard')
async def dashboard_page():
    token = app.storage.user.get('token')
    
    # 1. Kiểm tra đăng nhập
    if not token:
        ui.navigate.to('/')
        return

    # 2. KIỂM TRA QUYỀN (QUAN TRỌNG)
    role = get_user_role(token)
    if role != 'ADMIN':
        ui.notify('Bạn không có quyền truy cập Dashboard!', type='negative')
        ui.navigate.to('/profile') # Đá về trang profile
        return

    # ... (Code giao diện Dashboard giữ nguyên như cũ) ...
    # Hàm xử lý đăng xuất
    def logout():
        app.storage.user['token'] = None
        ui.notify('Đã đăng xuất', type='info')
        ui.navigate.to('/')

    # Header
    with ui.header().classes('bg-slate-800 text-white shadow-lg items-center'):
        ui.icon('storefront', size='32px').classes('mr-2')
        ui.label('ADMIN DASHBOARD').classes('text-lg font-bold') # Đổi tên cho rõ
        ui.space()
        with ui.row().classes('items-center'):
            ui.label(f'Role: {role}').classes('mr-4 font-light text-sm bg-slate-700 px-2 py-1 rounded')
            ui.button('Đăng xuất', on_click=logout, icon='logout').props('flat dense color=white')

    # Drawer & Content (Giữ nguyên logic cũ)
    with ui.left_drawer(value=True).classes('bg-slate-100'):
        with ui.column().classes('w-full q-pa-md'):
            ui.label('QUẢN TRỊ').classes('text-gray-500 text-xs font-bold mb-2')
            ui.button('Người dùng', icon='group').props('flat align=left').classes('w-full text-slate-700')

    with ui.column().classes('w-full p-8 bg-gray-50 min-h-screen'):
        ui.label('Quản lý toàn hệ thống').classes('text-2xl text-slate-800 mb-6')
        users = await get_users_api(token)
        if users:
            ui.table(
                columns=[
                    {'name': 'id', 'label': 'ID', 'field': 'id', 'sortable': True, 'align': 'left'},
                    {'name': 'email', 'label': 'Email', 'field': 'email', 'sortable': True, 'align': 'left'},
                    {'name': 'role', 'label': 'Vai trò', 'field': 'role', 'sortable': True, 'align': 'left'},
                ],
                rows=users,
                row_key='id'
            ).classes('w-full bg-white shadow-md rounded-lg')
#LOGIN PAGE#
@ui.page('/login')
def login_page():
    # Nếu đã đăng nhập thì chuyển luôn vào trong
    if app.storage.user.get('token'):
        role = get_user_role(app.storage.user.get('token'))
        if role == 'ADMIN':
            ui.navigate.to('/dashboard')
        else:
            ui.navigate.to('/profile')
        return

    async def handle_login():
        btn_login.props('loading')
        # Reset thông báo lỗi cũ
        notification.text = ""
        notification.classes('hidden')
        
        result = await login_api(email_input.value, pass_input.value)
        
        if result:
            app.storage.user['token'] = result['access_token']
            role = get_user_role(result['access_token'])
            
            ui.notify(f'Chào mừng {role} quay trở lại!', type='positive')
            if role == 'ADMIN':
                ui.navigate.to('/dashboard')
            else:
                ui.navigate.to('/profile')
        else:
            notification.text = "Email hoặc mật khẩu không chính xác!"
            notification.classes('block text-red-500 text-sm mt-2')
            ui.notify('Đăng nhập thất bại', type='negative')
        
        btn_login.props('remove-loading')

    # Nền trang Login (Sáng hơn chút để phân biệt)
    with ui.column().classes('w-full min-h-screen items-center justify-center bg-slate-100'):
        
        # Nút Back về trang chủ
        ui.button('Trang chủ', on_click=lambda: ui.navigate.to('/'), icon='arrow_back').props('flat text-color=grey').classes('absolute top-4 left-4')

        with ui.card().classes('w-full max-w-sm p-8 shadow-2xl rounded-xl'):
            # Header Form
            with ui.column().classes('w-full items-center mb-6'):
                with ui.avatar(color='blue-600', text_color='white', icon='lock').classes('shadow-lg mb-2'):
                    pass
                ui.label('ĐĂNG NHẬP').classes('text-2xl font-bold text-slate-800')
                ui.label('Nhập thông tin xác thực của bạn').classes('text-xs text-slate-500')

            # Inputs
            email_input = ui.input('Email').props('outlined dense').classes('w-full mb-3')
            pass_input = ui.input('Mật khẩu').props('outlined dense type=password').classes('w-full mb-4')
            
            # Thông báo lỗi (ẩn mặc định)
            notification = ui.label('').classes('hidden')

            # Button Submit
            btn_login = ui.button('Xác thực', on_click=handle_login).classes('w-full bg-blue-600 hover:bg-blue-700 text-white font-bold h-10 shadow-md')
            
            # Forgot password link (Fake)
            with ui.row().classes('w-full justify-center mt-4'):
                ui.link('Quên mật khẩu?', '#').classes('text-xs text-blue-500 no-underline hover:underline')
#--REGISTER PAGE--#
@ui.page('/register')
@ui.page('/register')
def register_page():
    if app.storage.user.get('token'):
        ui.navigate.to('/dashboard')
        return

    async def handle_register():
        if not email_input.value or not pass_input.value:
            ui.notify('Vui lòng nhập đầy đủ thông tin!', type='warning')
            return
        
        if pass_input.value != confirm_pass_input.value:
            ui.notify('Mật khẩu xác nhận không khớp!', type='negative')
            return

        btn_register.props('loading')
        notification.classes('hidden')

        # Gọi API
        success, result = await register_user_api(email_input.value, pass_input.value)
        
        if success:
            ui.notify('Đăng ký thành công! Đang chuyển hướng...', type='positive')
            ui.timer(1.5, lambda: ui.navigate.to('/login'))
        else:
            notification.text = f"Lỗi: {result}"
            notification.classes('block text-red-500 text-sm mt-2')
            ui.notify('Đăng ký thất bại', type='negative')
        
        btn_register.props('remove-loading')

    with ui.column().classes('w-full min-h-screen items-center justify-center bg-slate-100'):
        # Nút Back
        ui.button('Trang chủ', on_click=lambda: ui.navigate.to('/'), icon='home').props('flat text-color=grey').classes('absolute top-4 left-4')

        with ui.card().classes('w-full max-w-sm p-8 shadow-2xl rounded-xl'):
            with ui.column().classes('w-full items-center mb-6'):
                with ui.avatar(color='green-600', text_color='white', icon='person_add').classes('shadow-lg mb-2'):
                    pass
                ui.label('TẠO TÀI KHOẢN').classes('text-2xl font-bold text-slate-800')

            email_input = ui.input('Email').props('outlined dense').classes('w-full mb-3')
            pass_input = ui.input('Mật khẩu').props('outlined dense type=password').classes('w-full mb-3')
            confirm_pass_input = ui.input('Nhập lại Mật khẩu').props('outlined dense type=password').classes('w-full mb-4')
            
            notification = ui.label('').classes('hidden')

            btn_register = ui.button('Đăng ký ngay', on_click=handle_register).classes('w-full bg-green-600 hover:bg-green-700 text-white font-bold h-10 shadow-md')
            
            with ui.row().classes('w-full justify-center mt-4 gap-1'):
                ui.label('Đã có tài khoản?').classes('text-xs text-slate-500')
                ui.link('Đăng nhập', '/login').classes('text-xs text-blue-500 font-bold no-underline hover:underline')

# --- TRANG HOME(Trang chủ) ---
@ui.page('/')
def landing_page():
    # Nền Gradient tối màu hiện đại
    with ui.column().classes('w-full min-h-screen items-center justify-center bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white'):
        
        # --- Hero Section ---
        with ui.column().classes('items-center text-center max-w-4xl px-4'):
            ui.icon('hub', size='80px').classes('text-blue-400 mb-6 animate-bounce')
            ui.label('MICROSERVICE E-COMMERCE').classes('text-4xl md:text-6xl font-extrabold tracking-tight mb-4 bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-cyan-300')
            ui.label('Hệ thống E-commerce.').classes('text-lg md:text-xl text-slate-300 mb-10')
            
            # Group buttons
            with ui.row().classes('gap-4'):
                with ui.button(on_click=lambda: ui.navigate.to('/login')).classes('rounded-full px-8 py-3 bg-blue-500 hover:bg-blue-600 shadow-lg shadow-blue-500/50 transition-all hover:scale-105'):
                    with ui.row().classes('items-center gap-2'):
                        ui.label('ĐĂNG NHẬP').classes('font-bold tracking-wide')
                        ui.icon('login')
                
                with ui.button(on_click=lambda: ui.navigate.to('/register')).classes('rounded-full px-8 py-3 bg-transparent border-2 border-green-400 text-green-400 hover:bg-green-400 hover:text-slate-900 transition-all'):
                    with ui.row().classes('items-center gap-2'):
                        ui.label('ĐĂNG KÝ').classes('font-bold tracking-wide')
                        ui.icon('person_add')

        
        with ui.row().classes('mt-16 gap-6 justify-center flex-wrap px-4'):
            def feature_card(icon, title, desc):
                with ui.card().classes('w-64 bg-slate-800/50 border border-slate-700 p-6 backdrop-blur-sm hover:border-blue-500 transition-colors'):
                    ui.icon(icon, size='32px').classes('text-blue-400 mb-3')
                    ui.label(title).classes('text-lg font-bold mb-2')
                    ui.label(desc).classes('text-sm text-slate-400')

            feature_card('security', 'Bảo mật đa lớp', 'Authentication & Authorization với JWT và RBAC.')
            feature_card('speed', 'Hiệu năng cao', 'Kiến trúc Microservices vận hành độc lập.')
            feature_card('analytics', 'Giám sát Real-time', 'Theo dõi Log và Metrics tập trung.')

        # Footer
        ui.label('© 2025 E-commerce Project. Powered by Python & NiceGUI.').classes('mt-auto mb-4 text-slate-500 text-xs')

ui.run(title='E-commerce App', storage_secret='khoa_bi_mat', port=8080)
    