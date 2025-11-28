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

# --- TRANG LOGIN (Trang chủ) ---
@ui.page('/')
def login_page():
    if app.storage.user.get('token'):
        # Nếu đã login, kiểm tra role để điều hướng đúng chỗ
        token = app.storage.user.get('token')
        role = get_user_role(token)
        if role == 'ADMIN':
            ui.navigate.to('/dashboard')
        else:
            ui.navigate.to('/profile')
        return

    async def handle_login():
        btn_login.props('loading')
        result = await login_api(email_input.value, pass_input.value)
        
        if result:
            app.storage.user['token'] = result['access_token']
            
            # KIỂM TRA ROLE ĐỂ CHUYỂN HƯỚNG
            role = get_user_role(result['access_token'])
            ui.notify(f'Xin chào {role}!', type='positive')
            
            if role == 'ADMIN':
                ui.navigate.to('/dashboard')
            else:
                ui.navigate.to('/profile')
        else:
            ui.notify('Sai email hoặc mật khẩu!', type='negative')
            btn_login.props('remove-loading')

    with ui.column().classes('w-full h-screen items-center justify-center bg-slate-200'):
        with ui.card().classes('w-96 p-8 shadow-xl'):
            ui.label('ĐĂNG NHẬP').classes('text-2xl font-bold text-center w-full mb-6 text-slate-700')
            email_input = ui.input('Email').classes('w-full mb-4').props('outlined')
            pass_input = ui.input('Mật khẩu', password=True, password_toggle_button=True).classes('w-full mb-6').props('outlined')
            btn_login = ui.button('Vào hệ thống', on_click=handle_login).classes('w-full bg-blue-600 h-12')

ui.run(title='E-commerce App', storage_secret='khoa_bi_mat', port=8080)
    