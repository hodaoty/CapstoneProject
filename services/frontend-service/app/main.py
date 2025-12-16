from nicegui import ui, app
import httpx
import os
from jose import jwt

# --- 1. CẤU HÌNH & API ---
API_BASE_URL = os.environ.get("API_GATEWAY_URL", "http://api-gateway:80")

def get_user_role(token):
    try:
        payload = jwt.get_unverified_claims(token)
        return payload.get("role", "USER")
    except:
        return None

def get_user_email(token):
    try:
        payload = jwt.get_unverified_claims(token)
        return payload.get("sub")
    except:
        return None

async def login_api(username, password):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{API_BASE_URL}/api/auth/login",
                data={"username": username, "password": password},
                timeout=5.0
            )
            if response.status_code == 200:
                return response.json()
            return None
    except Exception as e:
        print(f"Login Error: {e}")
        return None

async def register_api(email, password):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{API_BASE_URL}/api/users/",
                json={"email": email, "password": password, "role": "USER"},
                timeout=5.0
            )
            if response.status_code == 200:
                return True, response.json()
            else:
                error_detail = response.json().get("detail", "Lỗi không xác định")
                return False, error_detail
    except Exception as e:
        print(f"Register Error: {e}")
        return False, str(e)

async def get_users_api(token):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{API_BASE_URL}/api/users/", headers=headers, timeout=5.0)
            if response.status_code == 200:
                return response.json()
            return []
    except:
        return []

async def get_products_api():
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{API_BASE_URL}/api/products/", timeout=5.0)
            if response.status_code == 200:
                return response.json()
            return []
    except Exception as e:
        print(f"Get Products Error: {e}")
        return []

async def create_product_api(token, data):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{API_BASE_URL}/api/products/",
                json=data,
                headers=headers,
                timeout=5.0
            )
            return response.status_code == 200
    except Exception as e:
        print(f"Create Product Error: {e}")
        return False

async def delete_product_api(token, product_id):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{API_BASE_URL}/api/products/{product_id}",
                headers=headers,
                timeout=5.0
            )
            return response.status_code == 200
    except Exception as e:
        print(f"Delete Product Error: {e}")
        return False

async def add_to_cart_api(token, user_email, product_id, quantity=1):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{API_BASE_URL}/api/cart/{user_email}",
                json={"product_id": product_id, "quantity": quantity},
                headers=headers,
                timeout=5.0
            )
            return response.status_code == 200
    except Exception as e:
        print(f"Add to Cart Error: {e}")
        return False

async def get_cart_api(token, user_email):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{API_BASE_URL}/api/cart/{user_email}",
                headers=headers,
                timeout=5.0
            )
            if response.status_code == 200:
                return response.json()
            return None
    except Exception as e:
        print(f"Get Cart Error: {e}")
        return None

async def remove_from_cart_api(token, user_email, product_id):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{API_BASE_URL}/api/cart/{user_email}/item/{product_id}",
                headers=headers,
                timeout=5.0
            )
            return response.status_code == 200
    except Exception as e:
        print(f"Remove from Cart Error: {e}")
        return False

async def get_product_detail_api(product_id):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{API_BASE_URL}/api/products/{product_id}", timeout=5.0)
            if response.status_code == 200:
                return response.json()
            return None
    except:
        return None

async def create_order_api(token, shipping_address):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{API_BASE_URL}/api/orders/",
                json={"shipping_address": shipping_address},
                headers=headers,
                timeout=10.0
            )
            if response.status_code == 200:
                return True, response.json()
            else:
                error_detail = response.json().get("detail", "Lỗi đặt hàng")
                return False, error_detail
    except Exception as e:
        print(f"Create Order Error: {e}")
        return False, str(e)

# --- [MỚI] API INVENTORY ---
async def get_inventory_api(product_id):
    """Lấy số lượng tồn kho của 1 sản phẩm"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{API_BASE_URL}/api/inventory/{product_id}", timeout=5.0)
            if response.status_code == 200:
                return response.json().get('quantity', 0)
            return 0
    except:
        return 0

async def update_inventory_api(token, product_id, change_quantity):
    """Cập nhật số lượng tồn kho (chỉ dành cho Staff/Admin)"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{API_BASE_URL}/api/inventory/update",
                json={"product_id": product_id, "change_quantity": int(change_quantity)},
                headers=headers,
                timeout=5.0
            )
            return response.status_code == 200
    except Exception as e:
        print(f"Update Inventory Error: {e}")
        return False


# --- 2. GIAO DIỆN CHUNG (Header/Layout) ---
def layout_header():
    """Thanh menu điều hướng dùng chung cho các trang"""
    with ui.header().classes('bg-slate-900 text-white shadow-md items-center h-16 px-4'):
        with ui.row().classes('items-center cursor-pointer').on('click', lambda: ui.navigate.to('/')):
            ui.icon('shopping_bag', size='32px').classes('text-blue-400 mr-2')
            ui.label('TECH STORE').classes('text-xl font-bold tracking-wider')
        
        ui.space()
        
        with ui.row().classes('items-center gap-4'):
            ui.link('Sản phẩm', '/products').classes('text-white no-underline hover:text-blue-300 font-medium cursor-pointer')
            
            token = app.storage.user.get('token')
            if token:
                role = get_user_role(token)
                if role == 'ADMIN':
                    ui.link('Admin Hub', '/admin').classes('text-orange-400 no-underline hover:text-orange-300 font-medium cursor-pointer')
                elif role == 'STAFF':
                     # Staff cũng được vào trang quản lý kho
                    ui.link('QL Kho', '/admin/inventory').classes('text-green-400 no-underline hover:text-green-300 font-medium cursor-pointer')

                if role != 'ADMIN' and role != 'STAFF':
                    ui.link('Giỏ hàng', '/cart').classes('text-white no-underline hover:text-blue-300 font-medium cursor-pointer')
                
                ui.link('Hồ sơ', '/profile').classes('text-white no-underline hover:text-blue-300 font-medium cursor-pointer')
                
                ui.button(icon='logout', on_click=lambda: (app.storage.user.update({'token': None}), ui.navigate.to('/'))).props('flat dense round color=white')
            else:
                ui.link('Đăng nhập', '/login').classes('text-white no-underline hover:text-blue-300 font-medium cursor-pointer')
                ui.button('Đăng ký', on_click=lambda: ui.navigate.to('/register')).classes('bg-blue-600 text-white px-4 py-1 rounded-full hover:bg-blue-700')

# --- 3. CÁC TRANG (PAGES) ---

@ui.page('/')
def landing_page():
    layout_header()
    with ui.column().classes('w-full min-h-screen items-center justify-center bg-slate-50 text-slate-800'):
        with ui.column().classes('items-center text-center max-w-4xl px-4 py-20'):
            ui.label('CÔNG NGHỆ TƯƠNG LAI').classes('text-5xl md:text-7xl font-black mb-6 text-slate-900')
            ui.label('Khám phá những sản phẩm công nghệ đỉnh cao với mức giá tốt nhất.').classes('text-xl text-slate-600 mb-10 max-w-2xl')
            ui.button('MUA SẮM NGAY', on_click=lambda: ui.navigate.to('/products')).classes('rounded-full px-10 py-4 bg-slate-900 text-white text-lg font-bold shadow-xl hover:scale-105 transition-transform')
        
        with ui.row().classes('w-full max-w-6xl gap-8 px-4 py-12 justify-center'):
            for i in range(3):
                with ui.card().classes('w-80 h-48 bg-white shadow-lg flex items-center justify-center border border-slate-200'):
                    ui.icon('star', size='48px').classes('text-yellow-400')
                    ui.label(f'Sản phẩm Hot {i+1}').classes('text-slate-500 font-bold ml-2')

@ui.page('/products')
async def products_page():
    layout_header()
    
    token = app.storage.user.get('token')
    user_email = get_user_email(token) if token else None

    async def handle_add_to_cart(product):
        if not token:
            ui.notify('Vui lòng đăng nhập để mua hàng!', type='warning')
            ui.navigate.to('/login')
            return
        
        success = await add_to_cart_api(token, user_email, product['id'], 1)
        if success:
            ui.notify(f'Đã thêm "{product["name"]}" vào giỏ!', type='positive', position='bottom-right')
        else:
            ui.notify('Lỗi khi thêm vào giỏ hàng.', type='negative')

    with ui.column().classes('w-full min-h-screen bg-gray-50'):
        with ui.row().classes('w-full bg-white p-8 border-b border-gray-200 mb-8 justify-center'):
            ui.label('SẢN PHẨM MỚI NHẤT').classes('text-3xl font-bold text-slate-800 tracking-wide')

        products = await get_products_api()
        
        if not products:
            with ui.column().classes('w-full items-center mt-10'):
                ui.icon('production_quantity_limits', size='64px').classes('text-gray-300 mb-4')
                ui.label('Chưa có sản phẩm nào.').classes('text-xl text-gray-500')
        else:
            with ui.element('div').classes('grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6 w-full max-w-7xl mx-auto px-4 mb-20'):
                for p in products:
                    with ui.card().classes('flex flex-col justify-between hover:shadow-xl transition-shadow duration-300 border border-gray-100 h-full bg-white overflow-hidden'):
                        ui.image(f'https://placehold.co/300x200/222/fff?text={p["name"][:3]}').classes('h-48 w-full object-cover')
                        with ui.column().classes('p-4 flex-grow w-full'):
                            category = p.get('category', 'General')
                            ui.label(category).classes('text-xs font-bold text-blue-500 uppercase tracking-wider mb-1')
                            ui.label(p['name']).classes('text-lg font-bold text-slate-900 leading-tight mb-2 line-clamp-2')
                            price = float(p['price'])
                            ui.label(f"${price:,.2f}").classes('text-xl font-bold text-green-600 mt-auto')
                        with ui.row().classes('w-full p-4 pt-0 mt-auto'):
                            ui.button('Thêm vào giỏ', icon='add_shopping_cart', on_click=lambda p=p: handle_add_to_cart(p)).classes('w-full bg-slate-900 text-white hover:bg-blue-600 transition-colors shadow-sm')

@ui.page('/cart')
async def cart_page():
    layout_header()
    token = app.storage.user.get('token')
    
    if not token: 
        ui.navigate.to('/login')
        return

    user_email = get_user_email(token)
    cart_items_detailed = []
    total_price = 0.0

    async def load_cart():
        nonlocal cart_items_detailed, total_price
        cart_data = await get_cart_api(token, user_email)
        if cart_data and cart_data.get('items'):
            items = cart_data['items']
            detailed_list = []
            temp_total = 0.0
            for item in items:
                p_id = item['product_id']
                qty = item['quantity']
                product_info = await get_product_detail_api(p_id)
                if product_info:
                    price = float(product_info['price'])
                    subtotal = price * qty
                    temp_total += subtotal
                    detailed_list.append({'id': p_id, 'name': product_info['name'], 'price': price, 'quantity': qty, 'subtotal': subtotal})
            cart_items_detailed = detailed_list
            total_price = temp_total
        else:
            cart_items_detailed = []
            total_price = 0.0

    await load_cart()

    @ui.refreshable
    def render_cart_ui():
        if not cart_items_detailed:
            with ui.column().classes('w-full items-center p-10 bg-white rounded-lg shadow-sm'):
                ui.icon('remove_shopping_cart', size='64px').classes('text-gray-300 mb-4')
                ui.label('Giỏ hàng trống').classes('text-xl text-gray-500 mb-6')
                ui.button('Tiếp tục mua sắm', on_click=lambda: ui.navigate.to('/products')).classes('bg-slate-900 text-white')
        else:
            with ui.row().classes('w-full gap-8 items-start'):
                with ui.card().classes('flex-grow shadow-sm'):
                    with ui.column().classes('w-full'):
                        with ui.row().classes('w-full p-4 bg-slate-100 font-bold text-slate-600'):
                            ui.label('Sản phẩm').classes('flex-grow')
                            ui.label('Đơn giá').classes('w-32 text-right')
                            ui.label('Số lượng').classes('w-24 text-center')
                            ui.label('Thành tiền').classes('w-32 text-right')
                            ui.label('').classes('w-10')

                        for item in cart_items_detailed:
                            with ui.row().classes('w-full p-4 border-b border-gray-100 items-center hover:bg-slate-50'):
                                ui.label(item['name']).classes('flex-grow font-medium text-slate-800')
                                ui.label(f"${item['price']:,.2f}").classes('w-32 text-right text-slate-600')
                                ui.label(str(item['quantity'])).classes('w-24 text-center font-bold')
                                ui.label(f"${item['subtotal']:,.2f}").classes('w-32 text-right font-bold text-slate-800')
                                ui.button(icon='delete', on_click=lambda i=item['id']: handle_remove(i)).props('flat dense round color=red')

                with ui.card().classes('w-96 shadow-lg p-6 sticky top-4'):
                    ui.label('Tóm tắt đơn hàng').classes('text-lg font-bold mb-4 border-b pb-2 w-full')
                    with ui.row().classes('w-full justify-between mb-2'):
                        ui.label('Tạm tính:')
                        ui.label(f"${total_price:,.2f}").classes('font-bold')
                    with ui.row().classes('w-full justify-between mb-6'):
                        ui.label('Phí vận chuyển:')
                        ui.label('Miễn phí').classes('text-green-600 font-bold')
                    with ui.row().classes('w-full justify-between mb-6 pt-4 border-t'):
                        ui.label('TỔNG CỘNG:').classes('text-xl font-bold')
                        ui.label(f"${total_price:,.2f}").classes('text-2xl font-bold text-blue-600')
                    
                    ui.button('THANH TOÁN NGAY', on_click=lambda: ui.navigate.to('/checkout')).classes('w-full bg-blue-600 text-white font-bold h-12 shadow-md hover:bg-blue-700')
                    ui.button('Tiếp tục mua sắm', on_click=lambda: ui.navigate.to('/products')).props('flat').classes('w-full mt-2 text-slate-500')

    async def handle_remove(product_id):
        success = await remove_from_cart_api(token, user_email, product_id)
        if success:
            ui.notify('Đã xóa sản phẩm', type='positive')
            await load_cart()
            render_cart_ui.refresh()
        else:
            ui.notify('Lỗi khi xóa', type='negative')

    with ui.column().classes('w-full min-h-screen bg-gray-50 p-8'):
        ui.label('GIỎ HÀNG CỦA BẠN').classes('text-3xl font-bold text-slate-800 mb-8')
        render_cart_ui()

@ui.page('/checkout')
async def checkout_page():
    layout_header()
    token = app.storage.user.get('token')
    if not token: ui.navigate.to('/login'); return

    user_email = get_user_email(token)
    cart_data = await get_cart_api(token, user_email)
    total_price = 0.0
    items_count = 0
    if cart_data and cart_data.get('items'):
        for item in cart_data['items']:
            p_id = item['product_id']
            qty = item['quantity']
            info = await get_product_detail_api(p_id)
            if info:
                total_price += float(info['price']) * qty
                items_count += 1
    else:
        ui.navigate.to('/products')
        return

    async def handle_place_order():
        if not name_input.value or not address_input.value or not phone_input.value:
            ui.notify('Vui lòng điền đầy đủ thông tin giao hàng!', type='warning')
            return

        btn_order.props('loading')
        full_shipping_info = f"{name_input.value}, Phone number: {phone_input.value}, Address: {address_input.value}"
        success, result = await create_order_api(token, full_shipping_info)
        if success:
            ui.notify('🎉 Đặt hàng thành công!', type='positive', close_button=True, timeout=5000)
            with ui.dialog() as dialog, ui.card():
                ui.label('Cảm ơn bạn đã mua hàng!').classes('text-xl font-bold text-green-600')
                ui.label(f'Mã đơn hàng: #{result.get("id")}').classes('text-slate-600')
                ui.button('Về trang chủ', on_click=lambda: ui.navigate.to('/')).classes('bg-slate-900 text-white mt-4')
            dialog.open()
        else:
            ui.notify(f'Lỗi đặt hàng: {result}', type='negative', close_button=True)
        btn_order.props('remove-loading')

    with ui.column().classes('w-full min-h-screen bg-gray-50 p-8'):
        ui.label('THANH TOÁN').classes('text-3xl font-bold text-slate-800 mb-8')
        with ui.row().classes('w-full gap-8 items-start'):
            with ui.card().classes('flex-grow shadow-sm p-6'):
                ui.label('1. Thông tin giao hàng').classes('text-xl font-bold text-slate-700 mb-4 border-b pb-2 w-full')
                with ui.column().classes('w-full gap-4'):
                    name_input = ui.input('Họ và tên').classes('w-full').props('outlined')
                    phone_input = ui.input('Số điện thoại').classes('w-full').props('outlined')
                    address_input = ui.textarea('Địa chỉ nhận hàng').classes('w-full').props('outlined')
                    ui.input('Ghi chú (Tùy chọn)').classes('w-full').props('outlined')
                ui.label('2. Phương thức thanh toán').classes('text-xl font-bold text-slate-700 mt-6 mb-4 border-b pb-2 w-full')
                ui.radio(['Thanh toán khi nhận hàng (COD)', 'Chuyển khoản ngân hàng'], value='Thanh toán khi nhận hàng (COD)').classes('ml-2')

            with ui.card().classes('w-96 shadow-lg p-6 sticky top-4'):
                ui.label('Đơn hàng của bạn').classes('text-lg font-bold mb-4 border-b pb-2 w-full')
                with ui.row().classes('w-full justify-between mb-2'):
                    ui.label(f'Sản phẩm ({items_count}):')
                    ui.label(f"${total_price:,.2f}")
                with ui.row().classes('w-full justify-between mb-6'):
                    ui.label('Vận chuyển:')
                    ui.label('Miễn phí').classes('text-green-600 font-bold')
                with ui.row().classes('w-full justify-between mb-6 pt-4 border-t'):
                    ui.label('TỔNG CỘNG:').classes('text-xl font-bold')
                    ui.label(f"${total_price:,.2f}").classes('text-2xl font-bold text-blue-600')
                btn_order = ui.button('ĐẶT HÀNG NGAY', on_click=handle_place_order).classes('w-full bg-red-600 text-white font-bold h-12 shadow-md hover:bg-red-700 text-lg')
                ui.button('Quay lại giỏ hàng', on_click=lambda: ui.navigate.to('/cart')).props('flat').classes('w-full mt-2 text-slate-500')

@ui.page('/login')
def login_page():
    if app.storage.user.get('token'): ui.navigate.to('/'); return
    async def handle_login():
        btn_login.props('loading'); notification.text = ""; notification.classes('hidden')
        result = await login_api(email_input.value, pass_input.value)
        if result:
            app.storage.user['token'] = result['access_token']
            role = get_user_role(result['access_token'])
            ui.notify(f'Chào mừng {role} quay trở lại!', type='positive')
            if role == 'ADMIN': 
                ui.navigate.to('/admin') # Đã sửa: Chuyển về trang Admin Hub
            else: 
                ui.navigate.to('/products')
        else:
            notification.text = "Email hoặc mật khẩu không chính xác!"
            notification.classes('block text-red-500 text-sm mt-2')
            ui.notify('Đăng nhập thất bại', type='negative')
        btn_login.props('remove-loading')

    with ui.column().classes('w-full min-h-screen items-center justify-center bg-slate-100'):
        ui.button('Trang chủ', on_click=lambda: ui.navigate.to('/'), icon='arrow_back').props('flat text-color=grey').classes('absolute top-4 left-4')
        with ui.card().classes('w-full max-w-sm p-8 shadow-2xl rounded-xl'):
            with ui.column().classes('w-full items-center mb-6'):
                with ui.avatar(color='blue-600', text_color='white', icon='lock').classes('shadow-lg mb-2'): pass
                ui.label('ĐĂNG NHẬP').classes('text-2xl font-bold text-slate-800')
            email_input = ui.input('Email').props('outlined dense').classes('w-full mb-3')
            pass_input = ui.input('Mật khẩu').props('outlined dense type=password').classes('w-full mb-4')
            notification = ui.label('').classes('hidden')
            btn_login = ui.button('Xác thực', on_click=handle_login).classes('w-full bg-blue-600 hover:bg-blue-700 text-white font-bold h-10 shadow-md')
            with ui.row().classes('w-full justify-center mt-4 gap-1'):
                ui.label('Chưa có tài khoản?').classes('text-xs text-slate-500')
                ui.link('Đăng ký ngay', '/register').classes('text-xs text-green-600 font-bold no-underline hover:underline')

@ui.page('/register')
def register_page():
    if app.storage.user.get('token'): ui.navigate.to('/dashboard'); return
    async def handle_register():
        if not email_input.value or not pass_input.value: return
        btn_register.props('loading')
        success, res = await register_api(email_input.value, pass_input.value)
        if success:
            ui.notify('Đăng ký thành công!', type='positive'); ui.timer(1.0, lambda: ui.navigate.to('/login'))
        else:
            ui.notify(f'Lỗi: {res}', type='negative')
        btn_register.props('remove-loading')

    with ui.column().classes('w-full h-screen items-center justify-center bg-slate-100'):
        ui.button(on_click=lambda: ui.navigate.to('/'), icon='home').props('flat round').classes('absolute top-4 left-4')
        with ui.card().classes('w-96 p-8 shadow-xl'):
            ui.label('ĐĂNG KÝ').classes('text-2xl font-bold text-center mb-6')
            email_input = ui.input('Email').classes('w-full mb-3')
            pass_input = ui.input('Mật khẩu', password=True).classes('w-full mb-4')
            btn_register = ui.button('Đăng ký', on_click=handle_register).classes('w-full bg-green-600 text-white')
            with ui.row().classes('w-full justify-center mt-4'):
                ui.link('Đã có tài khoản?', '/login').classes('text-sm text-blue-500')

# --- [MỚI] TRANG ADMIN HUB (/admin) ---
@ui.page('/admin')
def admin_hub_page():
    layout_header()
    token = app.storage.user.get('token')
    if not token: ui.navigate.to('/login'); return
    
    role = get_user_role(token)
    if role != 'ADMIN':
        ui.notify('Bạn không phải Admin!', type='negative')
        ui.navigate.to('/profile')
        return

    with ui.column().classes('w-full min-h-screen bg-gray-50 items-center justify-center p-8'):
        ui.label('TRUNG TÂM QUẢN TRỊ').classes('text-4xl font-black text-slate-800 mb-10 tracking-tight')
        
        with ui.row().classes('gap-8 justify-center flex-wrap'):
            # Card 1: Quản lý User
            with ui.card().classes('w-80 h-64 p-8 hover:scale-105 transition-transform cursor-pointer bg-gradient-to-br from-blue-600 to-blue-800 text-white shadow-xl items-center justify-center text-center').on('click', lambda: ui.navigate.to('/dashboard')):
                ui.icon('group', size='64px').classes('mb-4')
                ui.label('QUẢN LÝ NGƯỜI DÙNG').classes('text-xl font-bold tracking-wide')
                ui.label('Xem danh sách, phân quyền user.').classes('text-sm text-blue-100 mt-2')

            # Card 2: Quản lý Sản phẩm
            with ui.card().classes('w-80 h-64 p-8 hover:scale-105 transition-transform cursor-pointer bg-gradient-to-br from-orange-500 to-red-600 text-white shadow-xl items-center justify-center text-center').on('click', lambda: ui.navigate.to('/admin/products')):
                ui.icon('inventory_2', size='64px').classes('mb-4')
                ui.label('QUẢN LÝ SẢN PHẨM').classes('text-xl font-bold tracking-wide')
                ui.label('Thêm, xóa, cập nhật sản phẩm.').classes('text-sm text-orange-100 mt-2')
            
            # Card 3: Quản lý Kho (Thêm vào Admin Hub)
            with ui.card().classes('w-80 h-64 p-8 hover:scale-105 transition-transform cursor-pointer bg-gradient-to-br from-green-500 to-emerald-700 text-white shadow-xl items-center justify-center text-center').on('click', lambda: ui.navigate.to('/admin/inventory')):
                ui.icon('warehouse', size='64px').classes('mb-4')
                ui.label('QUẢN LÝ KHO').classes('text-xl font-bold tracking-wide')
                ui.label('Kiểm tra và cập nhật tồn kho.').classes('text-sm text-green-100 mt-2')

# --- TRANG ADMIN DASHBOARD (QUẢN LÝ USER) ---
@ui.page('/dashboard')
async def dashboard_page():
    layout_header()
    token = app.storage.user.get('token')
    if not token: ui.navigate.to('/login'); return
    role = get_user_role(token)
    if role != 'ADMIN': ui.navigate.to('/profile'); return

    # Nút quay lại Admin Hub
    with ui.column().classes('w-full p-8 bg-gray-50 min-h-screen'):
        with ui.row().classes('items-center mb-6'):
            ui.button(icon='arrow_back', on_click=lambda: ui.navigate.to('/admin')).props('flat round color=grey').classes('mr-4')
            ui.label('QUẢN LÝ NGƯỜI DÙNG').classes('text-2xl text-slate-800 font-bold')

        users = await get_users_api(token)
        if users:
            ui.table(columns=[{'name':'id','label':'ID','field':'id'}, {'name':'email','label':'Email','field':'email'}, {'name':'role','label':'Role','field':'role'}], rows=users, row_key='id').classes('bg-white shadow-sm w-full')

# --- TRANG ADMIN PRODUCTS (QUẢN LÝ SẢN PHẨM) ---
@ui.page('/admin/products')
async def admin_products_page():
    layout_header()
    token = app.storage.user.get('token')
    if not token: ui.navigate.to('/login'); return
    
    role = get_user_role(token)
    if role != 'ADMIN':
        ui.notify('Bạn không có quyền truy cập trang này!', type='negative')
        ui.navigate.to('/profile')
        return

    with ui.dialog() as add_dialog, ui.card().classes('w-96'):
        ui.label('Thêm Sản phẩm Mới').classes('text-xl font-bold mb-4')
        name_in = ui.input('Tên sản phẩm').classes('w-full')
        desc_in = ui.textarea('Mô tả').classes('w-full')
        price_in = ui.number('Giá', format='%.2f').classes('w-full')
        cat_in = ui.input('Danh mục').classes('w-full')
        
        async def submit_product():
            if not name_in.value or not price_in.value:
                ui.notify('Tên và giá là bắt buộc', type='warning')
                return
            data = {"name": name_in.value, "description": desc_in.value, "price": float(price_in.value), "category": cat_in.value}
            success = await create_product_api(token, data)
            if success:
                ui.notify('Thêm sản phẩm thành công!', type='positive')
                add_dialog.close()
                render_table.refresh()
            else:
                ui.notify('Lỗi khi thêm sản phẩm', type='negative')

        ui.button('Lưu', on_click=submit_product).classes('w-full bg-blue-600 text-white mt-4')

    async def delete_product(p_id):
        success = await delete_product_api(token, p_id)
        if success:
            ui.notify('Đã xóa sản phẩm', type='positive')
            render_table.refresh()
        else:
            ui.notify('Lỗi khi xóa', type='negative')

    @ui.refreshable
    async def render_table():
        products = await get_products_api()
        if products:
            with ui.card().classes('w-full'):
                with ui.row().classes('w-full bg-slate-100 p-3 font-bold'):
                    ui.label('ID').classes('w-10')
                    ui.label('Tên').classes('w-1/4')
                    ui.label('Giá').classes('w-32')
                    ui.label('Danh mục').classes('w-32')
                    ui.label('Hành động').classes('flex-grow text-right')
                
                for p in products:
                    with ui.row().classes('w-full p-3 border-b items-center hover:bg-gray-50'):
                        ui.label(str(p['id'])).classes('w-10')
                        ui.label(p['name']).classes('w-1/4 font-medium')
                        ui.label(f"${float(p['price']):,.2f}").classes('w-32 text-green-600')
                        ui.label(p.get('category', '')).classes('w-32 text-gray-500 text-sm')
                        with ui.row().classes('flex-grow justify-end'):
                             ui.button(icon='delete', color='red', on_click=lambda id=p['id']: delete_product(id)).props('flat dense round')

    # Nút quay lại Admin Hub
    with ui.column().classes('w-full p-8 bg-gray-50 min-h-screen'):
        with ui.row().classes('w-full justify-between items-center mb-6'):
            with ui.row().classes('items-center'):
                ui.button(icon='arrow_back', on_click=lambda: ui.navigate.to('/admin')).props('flat round color=grey').classes('mr-4')
                ui.label('QUẢN LÝ SẢN PHẨM').classes('text-2xl text-slate-800 font-bold')
            ui.button('Thêm Mới', icon='add', on_click=add_dialog.open).classes('bg-green-600 text-white')
        
        await render_table()

# --- [MỚI] TRANG QUẢN LÝ KHO (/admin/inventory) ---
@ui.page('/admin/inventory')
async def admin_inventory_page():
    layout_header()
    token = app.storage.user.get('token')
    if not token: ui.navigate.to('/login'); return
    
    role = get_user_role(token)
    if role not in ['ADMIN', 'STAFF']:
        ui.notify('Bạn không có quyền truy cập trang này!', type='negative')
        ui.navigate.to('/profile')
        return

    # Dialog nhập hàng
    with ui.dialog() as stock_dialog, ui.card().classes('w-96'):
        ui.label('Cập nhật tồn kho').classes('text-xl font-bold mb-4')
        selected_product_id = ui.number('Product ID', format='%.0f').classes('w-full hidden') # Lưu ID ẩn
        selected_product_name = ui.label('').classes('text-lg font-medium mb-4')
        quantity_in = ui.number('Số lượng thêm (nhập số âm để trừ)', value=10).classes('w-full')
        
        async def submit_stock():
            if not quantity_in.value: return
            
            # Gọi API update
            success = await update_inventory_api(token, selected_product_id.value, quantity_in.value)
            
            if success:
                ui.notify('Cập nhật kho thành công!', type='positive')
                stock_dialog.close()
                render_inventory_table.refresh()
            else:
                ui.notify('Lỗi cập nhật kho', type='negative')

        ui.button('Lưu Thay Đổi', on_click=submit_stock).classes('w-full bg-green-600 text-white mt-4')

    def open_stock_dialog(p_id, p_name):
        selected_product_id.value = p_id
        selected_product_name.text = f"Sản phẩm: {p_name}"
        quantity_in.value = 10 # Reset default
        stock_dialog.open()

    @ui.refreshable
    async def render_inventory_table():
        # Lấy danh sách sản phẩm trước
        products = await get_products_api()
        if products:
            with ui.card().classes('w-full'):
                with ui.row().classes('w-full bg-slate-100 p-3 font-bold'):
                    ui.label('ID').classes('w-10')
                    ui.label('Tên sản phẩm').classes('w-1/3')
                    ui.label('Tồn kho hiện tại').classes('w-32 text-center')
                    ui.label('Hành động').classes('flex-grow text-right')
                
                for p in products:
                    # Lấy số lượng tồn kho từng món (Hơi chậm nếu list dài, nhưng demo ok)
                    current_stock = await get_inventory_api(p['id'])
                    
                    with ui.row().classes('w-full p-3 border-b items-center hover:bg-gray-50'):
                        ui.label(str(p['id'])).classes('w-10 text-gray-500')
                        ui.label(p['name']).classes('w-1/3 font-medium')
                        
                        # Tô màu nếu hết hàng
                        stock_color = 'text-red-500 font-bold' if current_stock <= 0 else 'text-green-600 font-bold'
                        ui.label(str(current_stock)).classes(f'w-32 text-center {stock_color}')
                        
                        with ui.row().classes('flex-grow justify-end gap-2'):
                             ui.button('Nhập/Xuất', icon='edit', on_click=lambda id=p['id'], name=p['name']: open_stock_dialog(id, name)).props('flat dense size=sm color=blue')

    # Giao diện chính
    with ui.column().classes('w-full p-8 bg-gray-50 min-h-screen'):
        with ui.row().classes('w-full justify-between items-center mb-6'):
            with ui.row().classes('items-center'):
                # Nút quay lại (nếu là Admin thì về Hub, Staff thì về Profile hoặc đâu đó)
                back_link = '/admin' if role == 'ADMIN' else '/profile'
                ui.button(icon='arrow_back', on_click=lambda: ui.navigate.to(back_link)).props('flat round color=grey').classes('mr-4')
                ui.label('QUẢN LÝ KHO HÀNG').classes('text-2xl text-slate-800 font-bold')
            
            ui.button('Làm mới', icon='refresh', on_click=render_inventory_table.refresh).classes('bg-slate-700 text-white')
        
        await render_inventory_table()

@ui.page('/profile')
def profile_page():
    layout_header(); token = app.storage.user.get('token')
    if not token: ui.navigate.to('/login'); return
    role = get_user_role(token)
    with ui.column().classes('w-full items-center p-10 mt-10'):
        with ui.card().classes('p-8 items-center text-center shadow-lg w-96'):
            ui.avatar(icon='person', color='green', text_color='white', size='xl').classes('mb-4 shadow-md')
            ui.label(f'Xin chào, {role}').classes('text-2xl font-bold text-slate-700')
            ui.label('Thành viên thân thiết').classes('text-gray-500 mb-6')
            ui.button('Đăng xuất', on_click=lambda: (app.storage.user.update({'token': None}), ui.navigate.to('/'))).classes('bg-red-500 w-full')

# KHỞI CHẠY
ui.run(title='Tech Store', storage_secret='secret_key', port=8080)