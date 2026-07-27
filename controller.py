import queue
from ui import ControlWindowUi
from minesweeperhack import MinesweeperHack, threading

class ControlWindow(ControlWindowUi):
    def __init__(self):
        super().__init__()
        self.monitor_queue = queue.Queue()
        self.hack = MinesweeperHack(self.winfo_toplevel(), self.monitor_queue)
        handler_thread = threading.Thread(target=self._handle_queue_message, daemon=True)
        handler_thread.start()

    def _handle_queue_message(self): 
        while True: 
            message = self.monitor_queue.get() 
            if message is False:
                self.after(0, lambda: self.switch_vars['绘制雷区'].set(False)) 
                self.after(0, lambda: self.show_mines())

    def freeze_time(self):
        is_on = self.switch_vars['锁定时间'].get()
        if is_on:
            self.hack.freeze_time()
            self.log_info("🔒 时间已锁定")
        else:
            self.hack.stop_freeze_time()
            self.log_info("🔓 时间锁定已解除")
    
    def show_mines(self):
        is_on = self.switch_vars['绘制雷区'].get()
        if is_on:
            if self.hack.find_mines():
                self.log_info("💣 雷区已显示")
            else:
                self.log_info("⚠️ 请先开始游戏")
                self.switch_vars['绘制雷区'].set(False)
        else:
            self.hack.hide_mines()
            self.log_info("🙈 已取消雷区绘制")
    
    def be_invincible(self):
        is_on = self.switch_vars['无敌模式'].get()
        if is_on:
            self.hack.be_invincible()
            self.log_info("🛡️ 无敌模式已启用")
        else:
            self.hack.cancel_invincible()
            self.log_info("❌ 无敌模式已关闭")
    
    def click_equal_win(self):
        is_on = self.switch_vars['点击即赢'].get()
        if is_on:
            self.hack.click_equal_win()
            self.log_info("🎯 点击即赢已启用")
        else:
            self.hack.cancel_click_equal_win()
            self.log_info("📉 点击即赢已关闭")
    
    def modify_time(self):
        time_str = self.time_entry.get()
        if time_str:
            try:
                time_value = int(time_str)
                old_time_value = self.hack.modify_time(time_value)
                if old_time_value is not None:
                    self.log_info(f"⚙️ 原时间为：{old_time_value}，已将时间修改为: {time_value}")
                else:
                    self.log_info(f"❌️ 时间修改失败")
            except ValueError:
                self.log_info("❌ 输入无效，请输入正整数或0")
        else:
            self.log_info("⚠️ 请输入一个数字")
    
    def auto_win(self):
        is_on = self.switch_vars['点击即赢'].get()
        if is_on:
            self.log_info(f"❌️ 请先关闭点击即赢功能")
            return
        if not self.hack.auto_click():
            self.log_info(f"❌️ 请先开始游戏")
        else:
            self.log_info(f"🤖 自动游戏（SND）已完成")

    def self_define_mine(self):
        is_on = self.switch_vars['自定雷区'].get()
        if is_on:
            self.hack.sd_mines()
            self.log_info("🤪 自定雷区已启动")
            self.log_info("开启新的一局，点击第一下，将跳出雷区选择界面")
        else:
            self.hack.cancel_sd_mines()
            self.log_info("🤪 自定雷区已关闭")

    def lift_restrictions(self):
        is_on = self.switch_vars['允许0秒记录'].get()
        if is_on:
            self.hack.remove_restrictions()
            self.log_info("🛡️ 现在已经允许0秒记录")
            self.log_info("您可以尝试开启锁定时间功能，将时间修改为0秒，然后获胜")
        else:
            self.hack.add_restrictions()
            self.log_info("❌ 现在不再允许0秒记录")
    
    def show_mines_native(self):
        if not self.hack.find_mines_native():
            self.log_info(f"❌️ 请先开始游戏")
        else:
            self.log_info(f"💣 原生雷区已显示")
    
    def auto_win_quick(self):
        if not self.hack.auto_click_quick():
            self.log_info(f"❌️ 请先开始游戏")
        else:
            self.log_info(f"🤖 自动游戏（CALL）已完成")
            
    def auto_win_message(self):
        is_on = self.switch_vars['点击即赢'].get()
        if is_on:
            self.log_info(f"❌️ 请先关闭点击即赢功能")
            return
        if not self.hack.auto_click(True):
            self.log_info(f"❌️ 请先开始游戏")
        else:
            self.log_info(f"🤖 自动游戏（MSG）已完成")
            
    def auto_win_ultimate(self):
        is_on = self.switch_vars['点击即赢'].get()
        if is_on:
            self.log_info(f"❌️ 请先关闭点击即赢功能")
            return
        if not self.hack.ultimate_click():
            self.log_info(f"❌️ 请先开始游戏")
        else:
            self.log_info(f"🤖 自动游戏（ULT）已完成")
            
    def instant_win(self):
        if not self.hack.win_now():
            self.log_info(f"❌️ 请先开始游戏")
        else:
            self.log_info(f"⚡ 直接获胜已完成")
            self.log_info(f"此获胜方式不会更新统计信息")

