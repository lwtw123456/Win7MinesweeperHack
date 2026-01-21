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
            "restrictions_plus":("45 39 7D 08 74 40 48 8D 54 24 30", "45 39 7D 08 90 90 48 8D 54 24 30")
        }
        self._invincible_backend = None
        self._invincible_plus_backend = None
        self._click_equal_win_backend = None
        self._freeze_time_backend = None
        self._restrictions_backend = None
        self._restrictions_plus_backend = None
        self._monitor_thread = None
        self._monitor_thread_stop_event = threading.Event()
        self._click_equal_win_thread = None
        self._click_equal_win_thread_stop_event = threading.Event()
        self.editor = MemoryEditor("Minesweeper.exe")
        self.editor.connect()
        self._initialize_overlay(root)

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
            
    
    def _monitor_hwnds(self):
        while not self._monitor_thread_stop_event.is_set():
            time.sleep(0.5)
            hwnds = self.editor.get_hwnds()
            if sum(hwnd.get('is_enabled') is True for hwnd in hwnds) != 1 or next((d for d in hwnds if d.get('title') == '扫雷'), {}).get('is_enabled') is False:
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
                self._monitor_thread = threading.Thread(target=self._monitor_hwnds, daemon=True)
                self._monitor_thread.start()
            return True
    
    def hide_mines(self):
        self.overlay.hide()
        self._monitor_thread_stop_event.set()
        self._monitor_thread = None
        
    def auto_click(self, message=False):
        hwnds = self.editor.get_hwnds()
        if sum(hwnd.get('is_enabled') is True for hwnd in hwnds) != 1 or next((hwnd for hwnd in hwnds if hwnd.get('title') == '扫雷'), {}).get('is_enabled') is False:
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
            shellcode.extend([0x48, 0x83, 0xC4, 0x28,0xC3])
            self.editor.inject_shellcode(shellcode)
            return True
            
    def auto_click_quick(self):
        self._get_all_grid_data()
        rcx_value_addr = self.editor.calculate_pointer_chain(*self.paths["click_rcx"])
        target_function_addr = self.editor.calculate_pointer_chain(*self.paths["click_func"])
        shellcode = None
        while True:
            mines_grid_centers = self._get_mines_grid_centers()
            if not mines_grid_centers and not shellcode:
                first_click_rdx = self.editor.calculate_pointer_chain(*self.paths["first_click_rdx"])
                shellcode = bytearray([0x48, 0x83, 0xEC, 0x28])
                shellcode.extend([
                    0x48, 0xB9,                                 # mov rcx, imm64
                ])
                shellcode += struct.pack('<Q', rcx_value_addr)
                shellcode.extend([
                    0x49, 0x89, 0xCC,                          # mov r12, rcx
                ])
                shellcode.extend([
                    0x4D, 0x89, 0xE7,                          # mov r15, r12
                    0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
                    0x49, 0x83, 0xC7, 0x29,                    # add r15, 0x29
                    0x41, 0xC6, 0x07, 0x00                     # mov byte ptr [r15], 0x00
                ])
                shellcode.extend([
                    0x48, 0xBA,                                 # mov rdx, imm64
                ])
                shellcode += struct.pack('<Q', first_click_rdx)
                shellcode.extend([
                    0x48, 0x83, 0xEC, 0x20,                    # sub rsp, 0x20
                    0x48, 0xB8,                                # mov rax, imm64
                ])
                shellcode += struct.pack('<Q', target_function_addr)

                shellcode.extend([
                    0xFF, 0xD0,                                # call rax
                    0x48, 0x83, 0xC4, 0x20,                    # add rsp, 0x20
                ])
                shellcode.extend([
                    0x48, 0x83, 0xC4, 0x28,                    # add rsp, 0x28
                    0xC3,                                      # ret
                ])
                self.editor.inject_shellcode(shellcode)
            else:
                break
            time.sleep(0.1)
            
        mines_set = set(mines_grid_centers)
        need_set = set(self.all_grid_centers) - mines_set
        safe_first_rc = self._get_safe_cells_rc(need_set, mines_set)
        safe_first_rc.discard((0, 0))
        
        coord_count = len(safe_first_rc)
        buffer_size = 4 + (coord_count * 8)
        
        coords_address = self.editor.pm.allocate(buffer_size)
        buffer = struct.pack('<I', coord_count)
        
        for x, y in safe_first_rc:
            buffer += struct.pack('<ii', x, y)
        
        self.editor.write_value(coords_address, buffer, "bytes")
        
        rdx_value_addr = self.editor.calculate_pointer_chain(*self.paths["click_rdx"])
        sleep_addr = self.editor.get_winapi_func_addr("kernel32", "Sleep")

        shellcode = bytearray([0x48, 0x83, 0xEC, 0x28])

        shellcode.extend([
            0x41, 0x54,                                 # push r12
            0x41, 0x55,                                 # push r13
            0x41, 0x56,                                 # push r14
            0x41, 0x57,                                 # push r15
            0x56,                                       # push rsi
            0x57,                                       # push rdi
        ])

        shellcode.extend([
            0x48, 0xB9,                                 # mov rcx, imm64
        ])
        shellcode += struct.pack('<Q', rcx_value_addr)

        shellcode.extend([
            0x49, 0x89, 0xCC,                          # mov r12, rcx
        ])

        shellcode.extend([
            0x48, 0xB9,                                 # mov rcx, imm64
        ])
        shellcode += struct.pack('<Q', coords_address)
        shellcode.extend([
            0x48, 0x89, 0xCE,               # mov rsi, rcx 
            0x8B, 0x1E,                     # mov ebx, [rsi]
            0x48, 0x83, 0xC6, 0x04,         # add rsi, 4
        ])

        shellcode.extend([
            0x85, 0xDB,                     # test ebx, ebx
        ])

        jz_early_exit_pos = len(shellcode)
        shellcode.extend([
            0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,  # jz done
        ])
        
        shellcode.extend([
            0x4D, 0x89, 0xE7,                          # mov r15, r12
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x29,                    # add r15, 0x29
            0x41, 0xC6, 0x07, 0x00                     # mov byte ptr [r15], 0x00
        ])

        shellcode.extend([
            0x31, 0xFF,                     # xor edi, edi
        ])

        loop_start = len(shellcode)

        shellcode.extend([
            0x39, 0xDF,                     # cmp edi, ebx
        ])

        jge_pos = len(shellcode)
        shellcode.extend([
            0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00,  # jge done
        ])

        shellcode.extend([
            0x48, 0xC1, 0xE7, 0x03,        # shl rdi, 3
            0x8B, 0x4C, 0x3E, 0x04,        # mov ecx, [rsi+rdi+4]
            0x8B, 0x14, 0x3E,              # mov edx, [rsi+rdi]
            0x48, 0xC1, 0xEF, 0x03,        # shr rdi, 3
        ])

        shellcode.extend([
            0x4D, 0x89, 0xE7,                          # mov r15, r12
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x18,                    # add r15, 0x18
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x50,                    # add r15, 0x50
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,                    # add r15, 0x10
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x4D, 0x8D, 0x3C, 0xCF,                    # lea r15, [r15+rcx*8]
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,                    # add r15, 0x10
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x4D, 0x8D, 0x3C, 0x97,                    # lea r15, [r15+rdx*4]
        ])

        shellcode.extend([
            0x41, 0x80, 0x3F, 0x09                     # cmp byte ptr [r15], 9
        ])

        jne_skip_pos = len(shellcode)
        shellcode.extend([
            0x0F, 0x85, 0x00, 0x00, 0x00, 0x00,       # jne loop_continue
        ])

        shellcode.extend([
            0x4D, 0x89, 0xE7,                          # mov r15, r12
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,                    # add r15, 0x10
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x18,                    # add r15, 0x18
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x4D, 0x8D, 0x3C, 0xCF,                    # lea r15, [r15+rcx*8]
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,                    # add r15, 0x10
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x4D, 0x8D, 0x3C, 0xD7,                    # lea r15, [r15+rdx*8]
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
        ])

        shellcode.extend([
            0x49, 0xBB,                         # mov r11, imm64
        ])

        shellcode += struct.pack('<Q', rdx_value_addr)

        shellcode.extend([
            0x4D, 0x89, 0x3B,                          # mov [r11], r15
            0x49, 0x8B, 0x13,                          # mov rdx, [r11]
            0x4C, 0x89, 0xE1,                          # mov rcx, r12
            0x48, 0x83, 0xEC, 0x40,                    # sub rsp, 0x40
            0x48, 0xB8,                                # mov rax, imm64
        ])
        shellcode += struct.pack('<Q', target_function_addr)

        shellcode.extend([
            0xFF, 0xD0,                                # call rax
            0x48, 0x83, 0xC4, 0x40,                    # add rsp, 0x40
        ])

        shellcode.extend([
            0x48, 0x83, 0xEC, 0x20,                    # sub rsp, 0x20
            0x48, 0xC7, 0xC1, 0x64, 0x00, 0x00, 0x00,  # mov rcx, 100
            0x48, 0xB8,                                # mov rax, sleep
        ])
        shellcode += struct.pack('<Q', sleep_addr)
        shellcode.extend([
            0xFF, 0xD0,                                # call rax
            0x48, 0x83, 0xC4, 0x20,                    # add rsp, 0x20
        ])

        loop_continue_pos = len(shellcode)

        shellcode.extend([
            0xFF, 0xC7,                     # inc edi
        ])

        jmp_back_offset = loop_start - (len(shellcode) + 5)
        shellcode.extend([0xE9])
        shellcode += struct.pack('<i', jmp_back_offset)

        done_pos = len(shellcode)

        jz_offset = done_pos - (jz_early_exit_pos + 6)
        shellcode[jz_early_exit_pos + 2:jz_early_exit_pos + 6] = struct.pack('<i', jz_offset)

        jge_offset = done_pos - (jge_pos + 6)
        shellcode[jge_pos + 2:jge_pos + 6] = struct.pack('<i', jge_offset)

        jne_offset = loop_continue_pos - (jne_skip_pos + 6)
        shellcode[jne_skip_pos + 2:jne_skip_pos + 6] = struct.pack('<i', jne_offset)

        shellcode.extend([
            0x4D, 0x89, 0xE7,                          # mov r15, r12
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x29,                    # add r15, 0x29
            0x41, 0xC6, 0x07, 0x01                     # mov byte ptr [r15], 0x01
        ])


        shellcode.extend([
            0x4D, 0x31, 0xED,                          # xor r13, r13
        ])
        outer_loop_offset = len(shellcode)

        shellcode.extend([
            0x4D, 0x31, 0xF6,                          # xor r14, r14
        ])
        inner_loop_offset = len(shellcode)

        shellcode.extend([
            0x4D, 0x89, 0xE7,                          # mov r15, r12
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x18,                    # add r15, 0x18
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x50,                    # add r15, 0x50
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,                    # add r15, 0x10
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x4F, 0x8D, 0x3C, 0xF7,                    # lea r15, [r15+r14*8]
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,                    # add r15, 0x10
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x4F, 0x8D, 0x3C, 0xAF,                    # lea r15, [r15+r13*4]
        ])

        shellcode.extend([
            0x41, 0x80, 0x3F,0x09                # cmp byte ptr [r15], 9
        ])
        jne_to_continue_pos = len(shellcode)
        shellcode.extend([
            0x0F, 0x85,                                # jne rel32
            0x00, 0x00, 0x00, 0x00                     # placeholder
        ])

        shellcode.extend([
            0x4D, 0x8B, 0x3C, 0x24,
            0x49, 0x83, 0xC7, 0x18,
            0x4D, 0x8B, 0x3F,
            0x49, 0x83, 0xC7, 0x58,
            0x4D, 0x8B, 0x3F,
            0x49, 0x83, 0xC7, 0x10,
            0x4D, 0x8B, 0x3F,
            0x4F, 0x8D, 0x3C, 0xF7,
            0x4D, 0x8B, 0x3F,
            0x49, 0x83, 0xC7, 0x10,
            0x4D, 0x8B, 0x3F,
            0x4D, 0x01, 0xEF,
        ])

        shellcode.extend([
            0x41, 0x80, 0x3F, 0x00                          # cmp byte ptr [r15], 0
        ])
        je_offset_pos = len(shellcode)
        shellcode.extend([
            0x0F, 0x85,                                # jne rel32
            0x00, 0x00, 0x00, 0x00                     # placeholder
        ])

        shellcode.extend([
            0x4D, 0x89, 0xE7,                          # mov r15, r12
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,                    # add r15, 0x10
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x18,                    # add r15, 0x18
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x4F, 0x8D, 0x3C, 0xF7,                    # lea r15, [r15 + r14*8]
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x49, 0x83, 0xC7, 0x10,                    # add r15, 0x10
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
            0x4F, 0x8D, 0x3C, 0xEF,                    # lea r15, [r15 + r13*8]
            0x4D, 0x8B, 0x3F,                          # mov r15, [r15]
        ])
        shellcode.extend([
            0x49, 0xBB,                         # mov r11, imm64
        ])
        
        shellcode += struct.pack('<Q', rdx_value_addr)

        shellcode.extend([
            0x4D, 0x89, 0x3B,                   # mov [r11], r15
            0x49, 0x8B, 0x13,                   # mov rdx, [r11]
        ])
        
        shellcode.extend([
            0x4C, 0x89, 0xE1,                          # mov rcx, r12
            0x48, 0x83, 0xEC, 0x20,                    # sub rsp, 0x20
            0x48, 0xB8,                                # mov rax, imm64
        ])
        shellcode += struct.pack('<Q', target_function_addr)
        shellcode.extend([
            0xFF, 0xD0,                                # call rax
            0x48, 0x83, 0xC4, 0x20,                    # add rsp, 0x20
        ])
        shellcode.extend([
            0x48, 0x83, 0xEC, 0x20,                    # sub rsp, 0x20
            0x48, 0xC7, 0xC1, 0x14, 0x00, 0x00, 0x00,  # mov rcx, 20
            0x48, 0xB8,                                # mov rax, sleep
        ])
        shellcode += struct.pack('<Q', sleep_addr)
        shellcode.extend([
            0xFF, 0xD0,                                # call rax
            0x48, 0x83, 0xC4, 0x20,                    # add rsp, 0x20
        ])

        inner_continue_target = len(shellcode)

        jne_rel = inner_continue_target - (jne_to_continue_pos + 6)
        struct.pack_into('<i', shellcode, jne_to_continue_pos + 2, jne_rel)
        shellcode.extend([
            0x49, 0xFF, 0xC6,                          # inc r14
            0x49, 0x83, 0xFE, self.width & 0xFF
        ])
        inner_jump_offset = inner_loop_offset - (len(shellcode) + 6)
        shellcode.extend([0x0F, 0x82])
        shellcode += struct.pack('<i', inner_jump_offset)
        shellcode.extend([
            0x49, 0xFF, 0xC5,                          # inc r13
            0x49, 0x83, 0xFD, self.height & 0xFF
        ])
        outer_jump_offset = outer_loop_offset - (len(shellcode) + 6)
        shellcode.extend([0x0F, 0x82])
        shellcode += struct.pack('<i', outer_jump_offset)
        shellcode.extend([
            0x41, 0x5F,                                # pop r15
            0x41, 0x5E,                                # pop r14
            0x41, 0x5D,                                # pop r13
            0x41, 0x5C,                                # pop r12
            0x5F,                                      # pop rdi
            0x5E,                                      # pop rsi
            0x48, 0x83, 0xC4, 0x28,                    # add rsp, 0x28
            0xC3,                                      # ret
        ])

        rel = inner_continue_target - (je_offset_pos + 6)
        struct.pack_into('<i', shellcode, je_offset_pos + 2, rel)
        self.editor.inject_shellcode(shellcode)
        return True

