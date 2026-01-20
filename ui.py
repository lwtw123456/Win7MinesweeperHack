import tkinter as tk
from tkinter import ttk
from datetime import datetime

class ControlWindowUi(tk.Tk):
    """主界面"""
    def __init__(self):
        super().__init__()
        self.title("Win7版64位《扫雷》九项修改器")
        # 稍微增加窗口宽度以适应更多控件
        self.geometry("650x400")
        self.resizable(width=False, height=False)
        self._center_window()

        self.font_normal = ("微软雅黑", 10)
        self.switch_vars = {}
        
        # 注册验证命令
        vcmd = (self.register(self._validate_time_input), '%P')
        
        self._create_widgets(vcmd)

    def _center_window(self):
        """窗口居中显示通用方法"""
        self.update()
        win_width = self.winfo_width()
        win_height = self.winfo_height()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - win_width) // 2
        y = (screen_height - win_height) // 2
        self.geometry(f"{win_width}x{win_height}+{x}+{y}")

    def _validate_time_input(self, new_value):
        """验证时间输入框的内容"""
        if new_value == "":
            return True
        
        if not new_value.isdigit():
            return False
        
        try:
            value = int(new_value)
            if value >= 0:
                return True
        except ValueError:
            pass
        
        return False

    def _create_widgets(self, vcmd):
        """创建所有界面组件"""
        frame_switch = ttk.LabelFrame(self, text="功能开关区")
        frame_switch.pack(padx=15, pady=(15, 5), fill="x")
        
        switch_config = [
            ("锁定时间", self.freeze_time),
            ("绘制雷区", self.show_mines),
            ("无敌模式", self.be_invincible),
            ("点击即赢", self.click_equal_win),
            ("允许0秒记录", self.lift_restrictions),
        ]
        
        for idx, (text, func) in enumerate(switch_config):
            var = tk.BooleanVar(value=False)
            self.switch_vars[text] = var
            switch = ttk.Checkbutton(frame_switch, text=text, variable=var, width=12, command=func)
            switch.grid(row=0, column=idx, padx=8, pady=8)

        frame_button = ttk.LabelFrame(self, text="功能按钮区")
        frame_button.pack(padx=15, pady=(5, 10), fill="x")
        
        self.time_entry = ttk.Entry(
            frame_button, 
            width=8, 
            font=self.font_normal,
            validate='key',
            validatecommand=vcmd
        )
        self.time_entry.insert(0, "0")
        self.time_entry.grid(row=0, column=0, padx=(15, 5), pady=8, sticky="w")
        
        btn1 = ttk.Button(frame_button, text="修改时间", command=self.modify_time, width=12)
        btn1.grid(row=0, column=1, padx=5, pady=8, sticky="w")

        btn2 = ttk.Button(frame_button, text="显示雷区", command=self.show_mines_native, width=12)
        btn2.grid(row=0, column=2, padx=5, pady=8, sticky="w")

        btn2 = ttk.Button(frame_button, text="自动游戏(模拟鼠标)", command=self.auto_win, width=18)
        btn2.grid(row=0, column=3, padx=5, pady=8, sticky="w")
        
        btn3 = ttk.Button(frame_button, text="自动游戏(内存模式)", command=self.auto_win_quick, width=18)
        btn3.grid(row=0, column=4, padx=5, pady=8, sticky="w")

        frame_log = ttk.LabelFrame(self, text="运行日志区")
        frame_log.pack(padx=15, pady=(0, 15), fill="both", expand=True)
        
        scroll_log = ttk.Scrollbar(frame_log, orient="vertical")
        scroll_log.pack(side="right", fill="y")
        
        self.txt_log = tk.Text(
            frame_log, font=self.font_normal, wrap="word",
            yscrollcommand=scroll_log.set, state="disabled",
            bg="#f8f9fa", fg="#2d3436", selectbackground="#639fff",
            bd=0, highlightthickness=1, highlightcolor="#ced4da"
        )
        self.txt_log.pack(side="left", fill="both", expand=True, padx=(0, 5), pady=5)
        scroll_log.config(command=self.txt_log.yview)

        self.log_info("✅ 系统就绪，点击对应控件执行操作")

    def log_info(self, content):
        current_time = datetime.now().strftime("[%H:%M:%S]")
        log_content = f"{current_time} {content}\n"
        
        self.txt_log.config(state="normal")
        self.txt_log.insert(tk.END, log_content)
        self.txt_log.config(state="disabled")
        self.txt_log.see(tk.END)

    def freeze_time(self):
        pass

    def show_mines(self):
        pass

    def be_invincible(self):
        pass

    def click_equal_win(self):
        pass

    def modify_time(self):
        pass

    def auto_win(self):
        pass
    
    def lift_restrictions(self):
        pass
    
    def show_mines_native(self):
        pass
    
    def auto_win_quick(self):
        pass