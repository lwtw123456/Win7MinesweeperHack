from win_api import *
from PIL import Image
import time

def capture_window_to_pil(hwnd):
    rect = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return None

    width = rect.right - rect.left
    height = rect.bottom - rect.top
    if width <= 0 or height <= 0:
        return None

    hwnd_dc = user32.GetWindowDC(hwnd)
    if not hwnd_dc:
        return None

    mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
    bmp = gdi32.CreateCompatibleBitmap(hwnd_dc, width, height)
    gdi32.SelectObject(mem_dc, bmp)

    gdi32.BitBlt(mem_dc, 0, 0, width, height, hwnd_dc, 0, 0, SRCCOPY)

    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = width
    bmi.bmiHeader.biHeight = -height
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = 0

    buf_size = width * height * 4
    buf = ctypes.create_string_buffer(buf_size)
    gdi32.GetDIBits(mem_dc, bmp, 0, height, buf, ctypes.byref(bmi), DIB_RGB_COLORS)

    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem_dc)
    user32.ReleaseDC(hwnd, hwnd_dc)

    img = Image.frombuffer("RGBA", (width, height), buf, "raw", "BGRA", 0, 1).convert("RGB")
    return img

def detect_game_region(img: Image.Image):
    img_gray = img.convert('L')
    width, height = img_gray.size
    gray_pixels = img_gray.load()

    BIN_THRESH = 85
    MIN_CONTINUOUS = 100
    
    scan_start_x = int(width * 0.05)
    scan_start_y = int(height * 0.05)

    game_left = 0
    game_top = 0
    game_right = width - 1
    game_bottom = height - 1
    border_found = False
    
    for y in range(scan_start_y, height):
        if border_found:
            break
            
        in_black = False
        black_start_x = -1
        
        for x in range(scan_start_x, width):
            pixel = 0 if gray_pixels[x, y] < BIN_THRESH else 255
            
            if pixel == 0 and not in_black:
                in_black = True
                black_start_x = x
            elif pixel != 0 and in_black:
                black_end_x = x - 1
                in_black = False
                black_width = black_end_x - black_start_x + 1
                
                if black_width >= MIN_CONTINUOUS:
                    vertical_black_end_y = y
                    for check_y in range(y + 1, height):
                        if gray_pixels[black_start_x, check_y] < BIN_THRESH:
                            vertical_black_end_y = check_y
                        else:
                            break
                    
                    black_height = vertical_black_end_y - y + 1
                    if black_height >= MIN_CONTINUOUS:
                        game_left = black_start_x
                        game_top = y
                        game_right = black_end_x
                        game_bottom = vertical_black_end_y
                        border_found = True
                        break
    
    return (game_left, game_top, game_right, game_bottom)


def calc_grid_centers(region, rows, cols):
    min_x, min_y, max_x, max_y = region
    region_w = max_x - min_x
    region_h = max_y - min_y
    cell_w = region_w / cols
    cell_h = region_h / rows

    centers = []
    for r in range(rows):
        for c in range(cols):
            x1 = min_x + c * cell_w
            y1 = min_y + r * cell_h
            x2 = x1 + cell_w
            y2 = y1 + cell_h
            cx = int((x1 + x2) / 2)
            cy = int((y1 + y2) / 2)
            centers.append((cx, cy))
    return centers
    
def get_grid_centers(hwnd, rows, cols):
    img = capture_window_to_pil(hwnd)
    if img:
        region = detect_game_region(img)
        if region:
            centers = calc_grid_centers(region, rows, cols)
            return centers
    return None

def send_mouse_click(hwnd, x, y, click_type="left", restore_cursor=False, delay=0.05):
    old_pos = POINT()
    user32.GetCursorPos(ctypes.byref(old_pos))
    
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    
    screen_x = rect.left + x
    screen_y = rect.top + y
    
    user32.SetCursorPos(screen_x, screen_y)
    time.sleep(0.05)

    click_type = click_type.lower()
    if click_type == "left":
        user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
    elif click_type == "right":
        user32.mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0)
        user32.mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0)
    elif click_type == "middle":
        user32.mouse_event(MOUSEEVENTF_MIDDLEDOWN, 0, 0, 0, 0)
        user32.mouse_event(MOUSEEVENTF_MIDDLEUP, 0, 0, 0, 0)
    elif click_type == "double_click":
        user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
        time.sleep(0.03)
        user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
    else:
        raise ValueError(f"click_type仅支持：left/right/middle/double_click，你传入了：{click_type}")

    time.sleep(delay)
    if restore_cursor:
        user32.SetCursorPos(old_pos.x, old_pos.y)


def MAKELONG(low, high):
   return (high << 16) | (low & 0xFFFF)

def send_click_message(hwnd, x, y, click_type='left', delay=0.02):
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
   
    screen_x = rect.left + x
    screen_y = rect.top + y

    user32.SetCursorPos(screen_x, screen_y)

    screen_point = POINT(screen_x, screen_y)
    user32.ScreenToClient(hwnd, ctypes.byref(screen_point))

    lparam = MAKELONG(screen_point.x, screen_point.y)

    click_type = click_type.lower()
    if click_type == 'left':
       user32.SendMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lparam)
       user32.SendMessageW(hwnd, WM_LBUTTONUP, 0, lparam)
       
    elif click_type == 'right':
       user32.SendMessageW(hwnd, WM_RBUTTONDOWN, MK_RBUTTON, lparam)
       user32.SendMessageW(hwnd, WM_RBUTTONUP, 0, lparam)
       
    elif click_type == 'middle':
       user32.SendMessageW(hwnd, WM_MBUTTONDOWN, MK_MBUTTON, lparam)
       user32.SendMessageW(hwnd, WM_MBUTTONUP, 0, lparam)
       
    elif click_type == 'double':
       user32.SendMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lparam)
       user32.SendMessageW(hwnd, WM_LBUTTONUP, 0, lparam)
       time.sleep(0.03)
       user32.SendMessageW(hwnd, WM_LBUTTONDBLCLK, MK_LBUTTON, lparam)
       user32.SendMessageW(hwnd, WM_LBUTTONUP, 0, lparam)
    else:
       raise ValueError(f"不支持的点击类型: {click_type}")
       
    time.sleep(delay)

