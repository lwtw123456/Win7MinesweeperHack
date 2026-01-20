import tkinter as tk
from win_api import *

# =========================
# Overlay app
# =========================
class MinesweeperOverlay:
    def __init__(self, master, hwnd):

        self.target_hwnd = hwnd

        self.win = tk.Toplevel(master)
        self.win.title("Overlay_Temp")
        self.win.overrideredirect(True)
        self.win.wm_attributes("-topmost", True)
        self.win.wm_attributes("-transparentcolor", "white")
        self.win.configure(bg="white")

        self.win.update_idletasks()
        self.hwnd = self._get_tk_hwnd(self.win)
        if not self.hwnd:
            raise RuntimeError("❌ 获取 overlay HWND 失败")

        self._setup_transparent_clickthrough()

        self.left = self.top = self.right = self.bottom = 0
        self.current_width = 1
        self.current_height = 1
        self._update_pos()

        w = max(1, self.right - self.left)
        h = max(1, self.bottom - self.top)

        self.canvas = tk.Canvas(self.win, width=w, height=h, bg="white", highlightthickness=0)
        self.canvas.place(x=0, y=0)

        self.follow_interval = 100
        self._running = False
        self._timer_id = None

    def start(self, centers, queue):
        if self._running:
            return
        self.put_queue = queue
        self._update_pos()
        self._running = True
        self.win.deiconify()
        self._draw_centers(centers)
        self._schedule_tick()

    def hide(self):
        self._running = False
        self._cancel_tick()
        if hasattr(self, "canvas"):
            self.canvas.delete("all")

    def _get_tk_hwnd(self, win):
        try:
            hwnd = user32.GetParent(win.winfo_id())
            if hwnd and user32.IsWindow(hwnd):
                return int(hwnd)
        except Exception:
            pass
        return None

    def _setup_transparent_clickthrough(self):
        ex_style = user32.GetWindowLongW(self.hwnd, GWL_EXSTYLE)
        ex_style |= WS_EX_LAYERED | WS_EX_TRANSPARENT
        user32.SetWindowLongW(self.hwnd, GWL_EXSTYLE, ex_style)
        user32.SetLayeredWindowAttributes(self.hwnd, 0xFFFFFF, 0, LWA_COLORKEY)

    def _update_pos(self):
        rect = wintypes.RECT()
        if not user32.GetWindowRect(self.target_hwnd, ctypes.byref(rect)):
            raise RuntimeError("目标窗口可能已关闭")

        self.left, self.top, self.right, self.bottom = rect.left, rect.top, rect.right, rect.bottom
        w = max(1, self.right - self.left)
        h = max(1, self.bottom - self.top)

        self.win.geometry(f"{w}x{h}+{self.left}+{self.top}")
        if hasattr(self, "canvas"):
            self.canvas.config(width=w, height=h)

        self.current_width = w
        self.current_height = h

    def _draw_centers(self, centers):
        self.canvas.delete("all")

        r = 3
        for (cx, cy) in centers:
            self.canvas.create_oval(cx - r, cy - r, cx + r, cy + r, fill="red", outline="red")

    def _schedule_tick(self):
        if not self._running:
            return
        self._timer_id = self.win.after(self.follow_interval, self._tick)

    def _cancel_tick(self):
        if self._timer_id is not None:
            try:
                self.win.after_cancel(self._timer_id)
            except Exception:
                pass
            self._timer_id = None

    def _tick(self):
        if not self._running:
            self._timer_id = None
            return

        try:
            rect = wintypes.RECT()
            if not user32.GetWindowRect(self.target_hwnd, ctypes.byref(rect)):
                raise RuntimeError("目标窗口可能已关闭")

            new_left, new_top, new_right, new_bottom = rect.left, rect.top, rect.right, rect.bottom
            new_width = new_right - new_left
            new_height = new_bottom - new_top

            size_changed = (new_width != self.current_width or new_height != self.current_height)

            if (new_left != self.left or new_top != self.top or size_changed):
                self._update_pos()

                if size_changed:
                    self.put_queue.put(False)

        except Exception:
            self.hide()
            return

        self._schedule_tick()