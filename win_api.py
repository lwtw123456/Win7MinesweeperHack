import ctypes
from ctypes import wintypes, windll

# ========== 常量定义 ==========
# 窗口样式常量
GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x80000
WS_EX_TRANSPARENT = 0x20
LWA_COLORKEY = 0x01

# 鼠标操作常量
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040

# GDI相关常量
SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0

# 进程相关常量
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PAGE_EXECUTE_READWRITE = 0x40
MAX_MODULE_NAME_LENGTH = 260
MODULE_BUFFER_SIZE = 1024

# ========== DLL加载 ==========
user32 = ctypes.WinDLL("user32.dll", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32.dll", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
psapi = ctypes.WinDLL("psapi.dll", use_last_error=True)

# ========== User32 DLL 函数定义 ==========
# 分层窗口相关
user32.SetLayeredWindowAttributes.argtypes = [
    wintypes.HWND, wintypes.DWORD, wintypes.BYTE, wintypes.DWORD
]
user32.SetLayeredWindowAttributes.restype = wintypes.BOOL

# 窗口位置和大小
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowRect.restype = wintypes.BOOL

# 窗口样式
user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetWindowLongW.restype = ctypes.c_long
user32.SetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_long]
user32.SetWindowLongW.restype = ctypes.c_long

# 窗口状态
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.IsWindow.argtypes = [wintypes.HWND]
user32.IsWindow.restype = wintypes.BOOL

# 窗口关系
user32.GetParent.argtypes = [wintypes.HWND]
user32.GetParent.restype = wintypes.HWND

# 进程ID
user32.GetWindowThreadProcessId.argtypes = [
    wintypes.HWND, ctypes.POINTER(wintypes.DWORD)
]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD

# 窗口枚举
EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [EnumWindowsProc, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL

# ========== Kernel32 DLL 函数定义 ==========
# 进程操作
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

# 进程路径查询
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

# 内存保护
kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE,       
    ctypes.c_void_p,     
    ctypes.c_size_t,      
    wintypes.DWORD,   
    ctypes.POINTER(wintypes.DWORD) 
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

# ========== Psapi DLL 函数定义 ==========
# 模块枚举
psapi.EnumProcessModules.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.HMODULE),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)
]
psapi.EnumProcessModules.restype = wintypes.BOOL

# 模块信息
psapi.GetModuleInformation.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    ctypes.c_void_p,
    wintypes.DWORD
]
psapi.GetModuleInformation.restype = wintypes.BOOL

# 模块名称
psapi.GetModuleBaseNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    ctypes.c_wchar_p,
    wintypes.DWORD
]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD

# 模块文件路径
psapi.GetModuleFileNameExW.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    ctypes.c_wchar_p,
    wintypes.DWORD
]
psapi.GetModuleFileNameExW.restype = wintypes.DWORD

#相关结构体
class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", wintypes.DWORD * 3),
    ]
    
class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", wintypes.LPVOID),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", wintypes.LPVOID),
    ]
    
class POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]