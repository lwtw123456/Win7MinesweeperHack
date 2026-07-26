import pymem
import random
import threading
import pymem.exception
from win_api import *
import logging
from utils import get_grid_centers, send_mouse_click, send_click_message, time
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from memoryeditor import MemoryEditor
from minesweeperoverlay import MinesweeperOverlay
import struct
import os
import ctypes
from ctypes import wintypes


# WNDPROC_CLICK_HOOK_BEGIN
CLICK_HOOK_MESSAGE_NAME = "Win7MinesweeperHack.InternalClick.v2"
CLICK_HOOK_READY_PROPERTY = "Win7MinesweeperHack.WndProcHookReady.v2"
CLICK_HOOK_LAST_SEQUENCE_PROPERTY = "Win7MinesweeperHack.LastSequence.v2"
CLICK_HOOK_LAST_RESULT_PROPERTY = "Win7MinesweeperHack.LastResult.v2"

CLICK_HOOK_RESULT_SUCCESS = 1

user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
user32.RegisterWindowMessageW.restype = wintypes.UINT

user32.PostMessageW.argtypes = [
    wintypes.HWND,
    wintypes.UINT,
    ctypes.c_size_t,
    ctypes.c_ssize_t
]
user32.PostMessageW.restype = wintypes.BOOL

user32.GetPropW.argtypes = [
    wintypes.HWND,
    wintypes.LPCWSTR
]
user32.GetPropW.restype = wintypes.HANDLE
# WNDPROC_CLICK_HOOK_END



class MinesweeperHack:
    def __init__(self, root, queue):
        self.put_queue = queue
        self.paths = {
            "time": (0x000AAA38, [0x10, 0x38, 0x20]),
            'height': (0x000AAA38, [0x10, 0x38, 0x0C]),
            'width': (0x000AAA38, [0x10, 0x38, 0x10]),
            'mine_count': (0x000AAA38, [0x10, 0x38, 0x8]),
            'show_gird': (0x000AAA38, [0x10, 0x38, 0x18]),
            'mine': (0x000AAA38, [0x18, 0x58, 0x10, 0x0, 0x10, 0x0]),
            'status':(0x000AAA38, [0x18, 0x50, 0x10, 0x0, 0x10, 0x0]),
            'show_mine_rcx': (0xAAA38, [0x10]),
            'force_reveal_flag': (0xAAA38, [0x10, 0x40]),
            'should_refresh': (0xAAA38, [0x10, 0x114]),
            'engine_state': (0xAAA38, [0x38]),
            'show_mine_func': (0x32104, []),
            'click_rcx':(0xAAA38, []),
            'click_rdx':(0xAAB48, []),
            'click_func': (0x31854, []),
            'first_click_rdx': (0xAAA38, [0x10,0x18,0x0,0x10,0x0,0x0])
        }
        
        self.patterns_replace = {
            "invincible": ("48 89 B7 F8 00 00 00 B3 01 EB 1E", "90 90 90 90 90 90 90 B3 01 EB 1E"),
            "invincible_plus": ("44 88 A3 88 00 00 00 E9", "90 90 90 90 90 90 90 E9"),
            "freeze_time": ("48 8B 41 18 F3 0F 10 40 20 F3 0F 58 05 ?? ?? ?? ?? F3 0F 11 40 20", "48 8B 41 18 F3 0F 10 40 20 90 90 90 90 90 90 90 90 F3 0F 11 40 20"),
            "restrictions":("0F 44 D5 01 69 0C", "90 90 90 01 69 0C"),
            "restrictions_plus":("45 39 7D 08 74 40 48 8D 54 24 30", "45 39 7D 08 90 90 48 8D 54 24 30"),
            "click_perfect_1": ("75 0A 3B E8 0F 84 B6 02 00 00 FF C3", "FF C3 90 90 90 90 90 90 90 90 90 90"),
            "click_perfect_2": ("83 FE 0C 0F 85 DF 01 00 00", "83 FE 0C 90 90 90 90 90 90"),
            "click_perfect_3": ("83 F8 0A 0F 84 AB 00 00 00 83 F8 0B", "83 F8 0A 0F 84 93 02 00 00 83 F8 0B"),
            "click_perfect_4": ("40 38 3C 0E 75 1E", "40 38 3C 0E 90 90"),
            "click_perfect_patch":("48 8B 47 50 48 8B 48 10 4A 8B 04 E1", bytearray([0xE9]))
        }
        self._invincible_backend = None
        self._invincible_plus_backend = None
        self._click_equal_win_backend = None
        self._freeze_time_backend = None
        self._restrictions_backend = None
        self._restrictions_plus_backend = None
        self._click_perfect_shellcode_addr = None
        self._monitor_thread = None
        self._monitor_thread_stop_event = threading.Event()
        self._click_equal_win_thread = None
        self._click_equal_win_thread_stop_event = threading.Event()
        self.editor = MemoryEditor("Minesweeper.exe")
        self.editor.connect()
        self._initialize_overlay(root)

        # WNDPROC_CLICK_HOOK_STATE_BEGIN
        self._click_hook_dll = "MinesweeperWndProcHook.dll"
        self._click_hook_message = user32.RegisterWindowMessageW(
            CLICK_HOOK_MESSAGE_NAME
        )
        self._click_hook_sequence = 0
        self._click_hook_ready = False
        # WNDPROC_CLICK_HOOK_STATE_END

    def _initialize_overlay(self, root):
        try:
            self.main_hwnd = self.editor.get_hwnds()[0]['hwnd']
            self.overlay = MinesweeperOverlay(root, self.main_hwnd)
            self.overlay.hide()
        except Exception as e:
            print(f"❌ 初始化 overlay 失败: {e}")
            self.overlay = None

    def _click_equal_win_keep(self):
        while not self._click_equal_win_thread_stop_event.is_set():
            mine_count = self.editor.read_value(self.editor.calculate_pointer_chain(*self.paths["mine_count"]), "int")
            show_gird_address = self.editor.calculate_pointer_chain(*self.paths["show_gird"])
            self.editor.write_value(show_gird_address, self.height*self.width-mine_count, "int")
            time.sleep(0.5)
            
    
    def _monitor_state(self):
        final_address = self.editor.calculate_pointer_chain(*self.paths["engine_state"])
        while not self._monitor_thread_stop_event.is_set():
            time.sleep(0.5)
            if self.editor.read_value(final_address, "int") != 1:
                self.put_queue.put(False)
                break
    
    def _get_all_grid_data(self):
        height_address = self.editor.calculate_pointer_chain(*self.paths["height"])
        self.height = int(self.editor.read_value(height_address, "int"))
        width_address = self.editor.calculate_pointer_chain(*self.paths["width"])
        self.width = int(self.editor.read_value(width_address, "int"))
        self.all_grid_centers = get_grid_centers(self.main_hwnd, self.height, self.width)
        self.coord2idx = {coord: idx for idx, coord in enumerate(self.all_grid_centers)}
        
    def _iter_mines(self):
        mine_base_offset, mine_offsets = self.paths["mine"]
        mine_offsets = list(mine_offsets)

        for row in range(self.height):
            for col in range(self.width):
                mine_offsets[3] = col * 8
                mine_offsets[5] = row

                mine_address = self.editor.calculate_pointer_chain(mine_base_offset, mine_offsets)
                if self.editor.read_value(mine_address, "byte") == b'\x01':
                    idx = row * self.width + col
                    yield row, col, idx

    def _get_mines_grid_centers(self):
        return [self.all_grid_centers[idx] for _, _, idx in self._iter_mines()]

    def _is_game_started(self):
        return any(True for _ in self._iter_mines())

    def _get_mines_position(self):
        return [(row, col) for row, col, _ in self._iter_mines()]

    def _click_all_safe_cells(self, message = True):
        coord = None
        while True:
            mines_grid_centers = self._get_mines_grid_centers()
            if not mines_grid_centers:
                coord = self.all_grid_centers[0]
                idx = self.coord2idx[coord]
                row, col = divmod(idx, self.width)
                if not message:
                    self._click_with_verify(coord, row, col)
                else:
                    send_click_message(self.main_hwnd, *coord)
            else:
                break
            time.sleep(0.02)

        mines_set = set(mines_grid_centers)
        width = self.width
        height = self.height
        
        need_set = set(self.all_grid_centers) - mines_set
        if coord:
            need_set.discard(coord)

        status_base_offset, status_offsets = self.paths["status"]
        status_offsets = list(status_offsets)

        safe_first = self._get_safe_cells(need_set, mines_set)
        
        for round_num in range(3):
            for coord in tuple(safe_first):
                idx = self.coord2idx[coord]
                row, col = divmod(idx, width)
                if self._read_status(row, col, status_base_offset, status_offsets) == 9:
                    if not message:
                        self._click_with_verify(coord, row, col)
                    else:
                        send_click_message(self.main_hwnd, *coord)
                else:
                    safe_first.discard(coord)
                    need_set.discard(coord)
                if len(safe_first) == 0:
                    break

        if not message:
            status_read_set = set()

            for coord in list(need_set):
                idx = self.coord2idx[coord]
                row, col = divmod(idx, width)
                current_status = self._read_status(row, col, status_base_offset, status_offsets)
                
                if current_status >= 9:
                    if current_status > 9:
                        need_set.discard(coord)
                    continue

                neighbors = self._get_neighbors_by_index(coord)
                
                mine_neighbors = mines_set & neighbors
                mine_neighbors_to_count = mine_neighbors - status_read_set
                mine_count = len(mine_neighbors_to_count)
                
                unopened_neighbors = set()
                for neighbor_coord in neighbors:
                    if neighbor_coord in status_read_set:
                        continue
                        
                    neighbor_idx = self.coord2idx[neighbor_coord]
                    neighbor_row, neighbor_col = divmod(neighbor_idx, width)
                    neighbor_status = self._read_status(neighbor_row, neighbor_col, status_base_offset, status_offsets)
                    
                    if neighbor_status == 9:
                        unopened_neighbors.add(neighbor_coord)
                
                unopened_count = len(unopened_neighbors)
                unopened_non_mine_count = unopened_count - mine_count
                
                if unopened_non_mine_count == 0:
                    status_read_set.add(coord)
                    need_set.discard(coord)
                    continue
                
                if mine_count + 1 < unopened_non_mine_count:
                    for mine_coord in mine_neighbors_to_count:
                        mine_idx = self.coord2idx[mine_coord]
                        mine_row, mine_col = divmod(mine_idx, width)
                        self._click_with_verify(mine_coord, mine_row, mine_col, "right")
                        status_read_set.add(mine_coord)
                    
                    send_mouse_click(self.main_hwnd, *coord, "middle")
                    for unopened_neighbor_coord in unopened_neighbors: 
                        unopened_neighbors_idx = self.coord2idx[unopened_neighbor_coord] 
                        unopened_neighbors_row, unopened_neighbors_col = divmod(unopened_neighbors_idx, width) 
                        unopened_neighbor_status = self._read_status(unopened_neighbors_row, unopened_neighbors_col, status_base_offset, status_offsets) 
                        if unopened_neighbor_status == 9:
                            send_mouse_click(self.main_hwnd, *coord, "middle")
                    
                    for unopened_neighbor_coord in unopened_neighbors:
                        need_set.discard(unopened_neighbor_coord)
                else:
                    unopened_safe = unopened_neighbors - mine_neighbors_to_count
                    for safe_coord in unopened_safe:
                        safe_idx = self.coord2idx[safe_coord]
                        safe_row, safe_col = divmod(safe_idx, width)
                        self._click_with_verify(safe_coord, safe_row, safe_col)
                        need_set.discard(safe_coord)
                
                status_read_set.add(coord)
                need_set.discard(coord)
                
                
        for round_num in range(3):
            for coord in tuple(need_set):
                idx = self.coord2idx[coord]
                row, col = divmod(idx, width)
                if self._read_status(row, col, status_base_offset, status_offsets) == 9:
                    if not message:
                        self._click_with_verify(coord, row, col)
                    else:
                        send_click_message(self.main_hwnd, *coord)
                else:
                    need_set.discard(coord)
                if len(need_set) == 0:
                    break
        return True

    def _get_safe_cells(self, need_set, mines_set):
        safe_cells = set()
        
        for coord in need_set:
            neighbors = self._get_neighbors_by_index(coord)
            if not (neighbors & mines_set):
                safe_cells.add(coord)
        
        return safe_cells
        
    def _get_safe_cells_rc(self, need_set, mines_set):
        safe_cells_coord = self._get_safe_cells(need_set, mines_set)

        safe_cells_rc = set()
        for coord in safe_cells_coord:
            idx = self.coord2idx.get(coord)
            if idx is None:
                continue
            row, col = divmod(idx, self.width)
            safe_cells_rc.add((row, col))

        return safe_cells_rc

    def _get_neighbors_by_index(self, coord):
        if coord not in self.coord2idx:
            return set()
        
        idx = self.coord2idx[coord]
        row, col = divmod(idx, self.width)
        
        neighbor_offsets = [
            (-1, -1), (-1, 0), (-1, 1),
            (0, -1),           (0, 1),
            (1, -1),  (1, 0),  (1, 1)
        ]
        
        idx2coord = {idx: c for c, idx in self.coord2idx.items()}
        
        neighbors = set()
        for dr, dc in neighbor_offsets:
            neighbor_row = row + dr
            neighbor_col = col + dc
            
            if 0 <= neighbor_row < self.height and 0 <= neighbor_col < self.width:
                neighbor_idx = neighbor_row * self.width + neighbor_col
                neighbor_coord = idx2coord.get(neighbor_idx)
                
                if neighbor_coord:
                    neighbors.add(neighbor_coord)
        
        return neighbors

    def _read_status(self, row, col, status_base_offset, status_offsets):
        try:
            status_offsets[3] = col * 8
            status_offsets[5] = row * 4
            addr = self.editor.calculate_pointer_chain(status_base_offset, status_offsets)
            return self.editor.read_value(addr, "int")
        except Exception:
            return -1

    def _click_with_verify(self, coord, row, col, click_type="left"):
        send_mouse_click(self.main_hwnd, *coord, click_type=click_type)
        if self._read_status(row, col, self.paths["status"][0], self.paths["status"][1]) == 9:
            send_mouse_click(self.main_hwnd, *coord, click_type=click_type)
        
    def modify_time(self, new_value):
        try:
            final_address = self.editor.calculate_pointer_chain(*self.paths["time"])
            old_value = int(self.editor.read_value(final_address, "float"))
            if self.editor.write_value(final_address, new_value, "float"):
                return old_value
        except:
            return
        
    def freeze_time(self):
        if not self._freeze_time_backend:
            self._freeze_time_backend = self.editor.search_and_replace(*self.patterns_replace['freeze_time'], replace_all=False, base_only=True)
    
    def stop_freeze_time(self):
        if self._freeze_time_backend:
            for i in self._freeze_time_backend['data']:
                self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
        self._freeze_time_backend = None
        
    def be_invincible(self):
        if not self._invincible_backend or not self._invincible_plus_backend:
            self._invincible_backend = self.editor.search_and_replace(*self.patterns_replace['invincible'], replace_all=False, base_only=True)
            self._invincible_plus_backend = self.editor.search_and_replace(*self.patterns_replace['invincible_plus'], replace_all=False, base_only=True)
        
    def cancel_invincible(self):
        if self._invincible_backend and self._invincible_plus_backend:
            for i in self._invincible_backend['data']:
                self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
            for i in self._invincible_plus_backend['data']:
                self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
        self._invincible_backend = None
        self._invincible_plus_backend = None
            
    def click_equal_win(self):
        self._get_all_grid_data()
        if not self._click_equal_win_thread:
            self._click_equal_win_thread_stop_event.clear()
            self._click_equal_win_thread = threading.Thread(target=self._click_equal_win_keep, daemon=True)
            self._click_equal_win_thread.start()

    def cancel_click_equal_win(self):
        self._click_equal_win_thread_stop_event.set()
        self._click_equal_win_thread = None
        status_base_offset, status_offsets = self.paths["status"]
        status_offsets = list(status_offsets)
        show_gird = 0
        for coord in self.all_grid_centers:
            idx = self.coord2idx[coord]
            row, col = divmod(idx, self.width)
            if self._read_status(row, col, status_base_offset, status_offsets) != 9:
                show_gird += 1
        self.editor.write_value(self.editor.calculate_pointer_chain(*self.paths["show_gird"]), show_gird, "int")
            
    def find_mines(self):
        self._get_all_grid_data()
        mines_grid_centers = self._get_mines_grid_centers()
        if len(mines_grid_centers) == 0:
            return
        else:
            self.overlay.start(mines_grid_centers, self.put_queue)
            if not self._monitor_thread:
                self._monitor_thread_stop_event.clear()
                self._monitor_thread = threading.Thread(target=self._monitor_state, daemon=True)
                self._monitor_thread.start()
            return True
    
    def hide_mines(self):
        self.overlay.hide()
        self._monitor_thread_stop_event.set()
        self._monitor_thread = None
        
    def auto_click(self, message=False):
        final_address = self.editor.calculate_pointer_chain(*self.paths["engine_state"])
        if self.editor.read_value(final_address, "int") != 1:
            return
        self._get_all_grid_data()
        return self._click_all_safe_cells(message)
        
    def remove_restrictions(self):
        if not self._restrictions_backend or not self._restrictions_plus_backend:
            self._restrictions_backend = self.editor.search_and_replace(*self.patterns_replace['restrictions'], replace_all=False, base_only=True)
            self._restrictions_plus_backend = self.editor.search_and_replace(*self.patterns_replace['restrictions_plus'], replace_all=False, base_only=True)
            return True
            
    def add_restrictions(self):
        if self._restrictions_backend and self._restrictions_plus_backend:
            for i in self._restrictions_backend['data']:
                self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
            for i in self._restrictions_plus_backend['data']:
                self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
        self._restrictions_backend = None
        self._restrictions_plus_backend = None
        
    def find_mines_native(self):
        final_address = self.editor.calculate_pointer_chain(*self.paths["engine_state"])
        if self.editor.read_value(final_address, "int") != 1:
            return
        self._get_all_grid_data()
        if not self._is_game_started():
            return
        else:
            rcx_value_addr = self.editor.read_value(self.editor.calculate_pointer_chain(*self.paths["show_mine_rcx"]), "int")
            target_function_addr = self.editor.calculate_pointer_chain(*self.paths["show_mine_func"])
            shellcode = bytearray([0x48, 0x83, 0xEC, 0x28])
            shellcode.extend([0x48, 0xB9])
            shellcode += struct.pack('<Q', rcx_value_addr)
            shellcode.extend([0xC6, 0x41, 0x40, 0x01])
            shellcode.extend([0xC6, 0x81, 0x14, 0x01, 0x00, 0x00, 0x01])
            shellcode.extend([0x48, 0x83, 0xEC, 0x20])
            shellcode.extend([0x48, 0xB8])
            shellcode += struct.pack('<Q', target_function_addr)
            shellcode.extend([0xFF, 0xD0])
            shellcode.extend([0x48, 0x83, 0xC4, 0x20])
            shellcode.extend([0x48, 0x83, 0xC4, 0x28, 0xC3])
            self.editor.inject_shellcode(shellcode)
            return True
            

    def _ensure_click_hook(self):
        if not self._click_hook_message:
            self.editor.logger.error("注册自动点击消息失败")
            return False

        if user32.GetPropW(
                self.main_hwnd,
                CLICK_HOOK_READY_PROPERTY):
            self._click_hook_ready = True
            return True

        self._click_hook_ready = False

        if not self.editor.inject_dll(self._click_hook_dll):
            return False

        deadline = time.time() + 5.0
        while time.time() < deadline:
            if user32.GetPropW(
                    self.main_hwnd,
                    CLICK_HOOK_READY_PROPERTY):
                self._click_hook_ready = True
                return True
            time.sleep(0.02)

        self.editor.logger.error(
            "DLL已注入，但WndProc Hook未在5秒内就绪"
        )
        return False

    def _next_click_hook_sequence(self):
        self._click_hook_sequence = (
            self._click_hook_sequence + 1
        ) & 0x7FFFFFFF

        if self._click_hook_sequence == 0:
            self._click_hook_sequence = 1

        return self._click_hook_sequence

    def _get_click_cell_address(self, row, col):
        base_offset, offsets = self.paths["first_click_rdx"]
        offsets = list(offsets)
        offsets[2] = col * 8
        offsets[4] = row * 8

        return self.editor.calculate_pointer_chain(
            base_offset,
            offsets
        )

    def _click_cell_with_hook(
            self,
            row,
            col,
            status_base_offset,
            status_offsets,
            timeout=1.5):
        current_status = self._read_status(
            row,
            col,
            status_base_offset,
            status_offsets
        )

        if current_status != 9:
            return True

        cell_address = self._get_click_cell_address(
            row,
            col
        )
        sequence = self._next_click_hook_sequence()

        ctypes.set_last_error(0)
        result = user32.PostMessageW(
            self.main_hwnd,
            self._click_hook_message,
            sequence,
            cell_address
        )

        if not result:
            error_code = ctypes.get_last_error()
            self.editor.logger.error(
                f"PostMessageW失败，错误码: {error_code}"
            )
            return False

        engine_state_address = (
            self.editor.calculate_pointer_chain(
                *self.paths["engine_state"]
            )
        )

        deadline = time.time() + timeout
        while time.time() < deadline:
            current_status = self._read_status(
                row,
                col,
                status_base_offset,
                status_offsets
            )

            if current_status != 9:
                return True

            if self.editor.read_value(
                    engine_state_address,
                    "int") != 1:
                return True

            handled_sequence = int(
                user32.GetPropW(
                    self.main_hwnd,
                    CLICK_HOOK_LAST_SEQUENCE_PROPERTY
                ) or 0
            )

            if handled_sequence == sequence:
                hook_result = int(
                    user32.GetPropW(
                        self.main_hwnd,
                        CLICK_HOOK_LAST_RESULT_PROPERTY
                    ) or 0
                )

                if hook_result != CLICK_HOOK_RESULT_SUCCESS:
                    self.editor.logger.error(
                        "WndProc内部点击失败，"
                        f"结果码: {hook_result}"
                    )
                    return False

            time.sleep(0.001)

        self.editor.logger.error(
            f"等待格子打开超时: row={row}, col={col}"
        )
        return False

    @staticmethod
    def _has_neighbor_mine(
            row,
            col,
            height,
            width,
            mines_set):
        for row_offset in (-1, 0, 1):
            for col_offset in (-1, 0, 1):
                if row_offset == 0 and col_offset == 0:
                    continue

                neighbor_row = row + row_offset
                neighbor_col = col + col_offset

                if (
                    0 <= neighbor_row < height
                    and 0 <= neighbor_col < width
                    and (
                        neighbor_row,
                        neighbor_col
                    ) in mines_set
                ):
                    return True

        return False

    def auto_click_quick(self):
        final_address = self.editor.calculate_pointer_chain(
            *self.paths["engine_state"]
        )

        if self.editor.read_value(
                final_address,
                "int") != 1:
            return

        self._get_all_grid_data()

        if not self._ensure_click_hook():
            return

        status_base_offset, status_offsets = (
            self.paths["status"]
        )
        status_offsets = list(status_offsets)

        if not self._is_game_started():
            if not self._click_cell_with_hook(
                    0,
                    0,
                    status_base_offset,
                    status_offsets):
                return

            deadline = time.time() + 2.0
            while time.time() < deadline:
                if self._is_game_started():
                    break

                if self.editor.read_value(
                        final_address,
                        "int") != 1:
                    return

                time.sleep(0.01)
            else:
                self.editor.logger.error(
                    "第一次点击后雷区未生成"
                )
                return

        mines_set = set(
            self._get_mines_position()
        )

        safe_cells = [
            (row, col)
            for row in range(self.height)
            for col in range(self.width)
            if (row, col) not in mines_set
        ]

        safe_cells.sort(
            key=lambda cell: (
                self._has_neighbor_mine(
                    cell[0],
                    cell[1],
                    self.height,
                    self.width,
                    mines_set
                ),
                cell[0],
                cell[1]
            )
        )

        for row, col in safe_cells:
            if self.editor.read_value(
                    final_address,
                    "int") != 1:
                break

            if self._read_status(
                    row,
                    col,
                    status_base_offset,
                    status_offsets) != 9:
                continue

            if not self._click_cell_with_hook(
                    row,
                    col,
                    status_base_offset,
                    status_offsets):
                return

        return True

    def win_now(self):
        final_address = self.editor.calculate_pointer_chain(*self.paths["engine_state"])
        if self.editor.read_value(final_address, "int") != 1:
            return
        self.editor.write_value(final_address, 3, "int")
        return True

    def ultimate_click(self):
        final_address = self.editor.calculate_pointer_chain(*self.paths["engine_state"])
        if self.editor.read_value(final_address, "int") != 1:
            return
                
        click_perfect_1_backend = self.editor.search_and_replace(*self.patterns_replace["click_perfect_1"], replace_all=False, base_only=True)
        click_perfect_2_backend = self.editor.search_and_replace(*self.patterns_replace["click_perfect_2"], replace_all=False, base_only=True)
        click_perfect_3_backend = self.editor.search_and_replace(*self.patterns_replace["click_perfect_3"], replace_all=False, base_only=True)
        click_perfect_4_backend = self.editor.search_and_replace(*self.patterns_replace["click_perfect_4"], replace_all=False, base_only=True)
        
        rcx_value_addr = self.editor.calculate_pointer_chain(*self.paths["click_rcx"])
        
        patch_address = self.editor.search(self.patterns_replace["click_perfect_patch"][0], False)[0]['address']
        shellcode = bytearray()
        
        shellcode.extend([
            0x41, 0x57,                         # push r15
            0x48, 0xB9                          # mov rcx, imm64
        ])
        shellcode += struct.pack('<Q', rcx_value_addr)

        shellcode.extend([
            0x4C, 0x8B, 0xF9,                   # mov r15, rcx
            0x48, 0x8B, 0x09,                   # mov rcx, [rcx]
            0x48, 0x83, 0xC1, 0x18,             # add rcx, 0x18
            0x48, 0x8B, 0x09,                   # mov rcx, [rcx]
            0x48, 0x83, 0xC1, 0x58,             # add rcx, 0x58
            0x48, 0x8B, 0x09,                   # mov rcx, [rcx]
            0x48, 0x83, 0xC1, 0x10,             # add rcx, 0x10
            0x48, 0x8B, 0x09,                   # mov rcx, [rcx]
            0x4A, 0x8B, 0x0C, 0xE1,             # mov rcx, [rcx+r12*8]
            0x48, 0x83, 0xC1, 0x10,             # add rcx, 0x10
            0x48, 0x8B, 0x09,                   # mov rcx, [rcx]
            0x48, 0x8D, 0x0C, 0x29,             # lea rcx, [rcx+rbp]
            0x80, 0x39, 0x00,                   # cmp byte ptr [rcx], 0
            0x48, 0x8B, 0x47, 0x50,             # mov rax,qword ptr ds:[rdi+50]
            0x48, 0x8B, 0x48, 0x10,             # mov rcx,qword ptr ds:[rax+10]
            0x4A, 0x8B, 0x04, 0xE1,             # mov rax,qword ptr ds:[rcx+r12*8]
            0x48, 0x8B, 0x48, 0x10,             # mov rcx,qword ptr ds:[rax+10]
            0x74, 0x27,                         # jz 0x27
            0x83, 0x3c, 0xa9, 0x09,             # cmp dword ptr ds:[rcx+rbp*4],9
            0x74, 0x07,                         # jz 0x07
            0xBB, 0x0A, 0x00, 0x00, 0x00,       # mov ebx, 10
            0xEB, 0x05,                         # jmp 0x05
            0xBB, 0x0B, 0x00, 0x00, 0x00,       # mov ebx, 11
            0x4D, 0x8B, 0x3F,                   # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,             # add r15, 0x10
            0x4D, 0x8B, 0x3F,                   # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x38,             # add r15, 0x38
            0x4D, 0x8B, 0x3F,                   # mov r15, [r15]
            0x41, 0xFF, 0x4F, 0x18,             # dec dword ptr [r15+18]
            0X41, 0X5f,                         # pop r15
            0x89, 0x1C, 0xA9                    # mov dword ptr ds:[rcx+rbp*4],ebx
        ])
        
        jmp_offset_pos = len(shellcode)
        shellcode.extend([
            0xE9,                               # jmp rel32
            0x00, 0x00, 0x00, 0x00,             # placeholder
        ])
        
        if not self._click_perfect_shellcode_addr:
            self._click_perfect_shellcode_addr = self.editor.alloc_near(patch_address, len(shellcode))
        
        jmp_offset = (patch_address + 24) - (self._click_perfect_shellcode_addr + jmp_offset_pos + 5)
        shellcode[jmp_offset_pos + 1:jmp_offset_pos + 5] = struct.pack('<i', jmp_offset)
        
        if len(self.patterns_replace["click_perfect_patch"][1]) == 1:
            rel32 = self._click_perfect_shellcode_addr - (patch_address + 5)
            self.patterns_replace["click_perfect_patch"] = list(self.patterns_replace["click_perfect_patch"])
            self.patterns_replace["click_perfect_patch"][1] += struct.pack('<i', rel32)
            self.patterns_replace["click_perfect_patch"][1].extend([0x90, 0x90, 0x90])
            self.patterns_replace["click_perfect_patch"] = tuple(self.patterns_replace["click_perfect_patch"])
        
        click_perfect_patch_backend = self.editor.search_and_replace(*self.patterns_replace["click_perfect_patch"], replace_all=False, base_only=True)
        
        self.editor.write_value(self._click_perfect_shellcode_addr, shellcode, "bytes")
        
        self._get_all_grid_data()
        status_base_offset, status_offsets = self.paths["status"]
        status_offsets = list(status_offsets)
        for coord in self.all_grid_centers:
            idx = self.coord2idx[coord]
            row, col = divmod(idx, self.width)
            if self._read_status(row, col, status_base_offset, status_offsets) == 9:
                while True:
                    send_click_message(self.main_hwnd, *coord)
                    if self._read_status(row, col, status_base_offset, status_offsets) != 9:
                        break
                    time.sleep(0.1)
            if self.editor.read_value(final_address, "int") != 1:
                break

        for i in click_perfect_1_backend['data']:
            self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
        for i in click_perfect_2_backend['data']:
            self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
        for i in click_perfect_3_backend['data']:
            self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
        for i in click_perfect_4_backend['data']:
            self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
        for i in click_perfect_patch_backend['data']:
            self.editor.search_and_replace(i['new'], i['original'], replace_all=False, base_only=True)
        return True
