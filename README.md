# Win7MinesweeperHack

> 🎯 一个针对 **Windows 7 64 位版《扫雷》(Minesweeper.exe)** 的学习型修改器项目。
> 主要用于 **逆向工程 / 内存分析 / Windows API / Python 自动化 / Tkinter GUI** 的研究与交流。

⚠️ **本项目仅用于技术学习与研究，请勿用于任何商业用途或破坏他人环境。**

---

## ✨ 功能特性

当前版本实现了以下功能（部分基于内存修改，部分基于代码注入）：

- ⏱️ **锁定时间**
- ✏️ **手动修改时间**
- 💣 **绘制雷区（Overlay 覆盖层显示）**
- 💣 **原生方式显示雷区（Shellcode 注入）**
- 🛡️ **无敌模式（踩雷不死）**
- 🎯 **点击即赢**
- 🤖 **自动扫雷（SendInput）**
- 🤖 **自动扫雷（SendMessage）**
- ⚡ **自动扫雷（call）**
- 🚫 **解除 0 秒通关限制**

GUI 使用 **Tkinter** 构建，操作直观。

---

## 🖼️ 程序界面

- 主界面：功能开关 + 功能按钮 + 日志输出
- Overlay：透明窗口实时覆盖雷区位置

---

## 🧱 项目结构

```text
.
├── main.py                  # 程序入口
├── controller.py            # 主控制器
├── ui.py                    # UI 界面定义
├── minesweeperhack.py       # 核心修改逻辑
├── memoryeditor.py          # 通用内存编辑引擎
├── minesweeperoverlay.py    # Overlay 覆盖层
├── utils.py                 # 图像识别 & 鼠标控制工具
├── win_api.py               # Windows API / ctypes 封装
└── README.md
```

---

## 🔧 运行环境

- Python 3.8+

### Python 依赖

```bash
pip install pymem pillow
```

---

## ▶️ 使用方法

1. 运行扫雷
2. 启动本程序

```bash
python main.py
```

3. 进入扫雷游戏后，再启用对应功能

---

## 🧠 技术点说明

本项目涉及但不限于以下技术：

- Windows 进程内存读写（`pymem`）
- 指针链计算
- 特征码扫描（AOB Scan）
- 内存保护修改（`VirtualProtectEx`）
- Shellcode 注入 & 远程线程
- Windows API（User32 / GDI / Kernel32）
- Tkinter GUI
- 覆盖窗口（透明 + 穿透）
- 自动化鼠标控制
- 扫雷逻辑推导

非常适合作为：

> 🔍 **Windows 游戏逆向 / Python Hack Tool 入门项目**

---

## ⚠️ 注意事项

- **仅支持 Win7 64 位原版扫雷**
- 杀毒软件可能会误报（涉及内存操作）
- 请勿用于任何比赛、排行或破坏他人数据

---

## 📜 免责声明

本项目 **仅用于学习与研究目的**。  
因使用本程序造成的任何后果，作者概不负责。

如果你用于：

- 逆向工程学习 ✅
- Windows 内存机制研究 ✅
- Python + WinAPI 学习 ✅

那非常欢迎 👍

---

## 📄 开源协议

本项目基于 MIT License
开源，可自由用于个人或商业用途，但需保留版权声明。

---

## ⭐ Star

如果你觉得这个项目对你有帮助，欢迎 Star ⭐  
也欢迎 Fork / PR / Issue 交流实现思路。

---

**Enjoy reverse engineering! 🧠🔥**
