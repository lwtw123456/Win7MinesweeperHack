import threading
import pymem.exception
from win_api import *
import logging
import time
import pymem
import sys


class MemoryEditor:
    """内存编辑器类"""
    def __init__(self, process_name, verbose=True):
        self.process_name = process_name
        self.pm = None
        self.base_module_info = None
        self._lock_threads = {}
        self._lock_counter = 0
        self._lock_threads_lock = threading.Lock()
        self.logger = logging.getLogger(f"MemoryEditor.{process_name}")
        
        if verbose:
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('[%(levelname)s] %(message)s')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        else:
            if not self.logger.handlers:
                self.logger.addHandler(logging.NullHandler())
            self.logger.setLevel(logging.CRITICAL + 1)

    def connect(self):
        """连接到进程"""
        try:
            self.pm = pymem.Pymem(self.process_name)
        except pymem.exception.ProcessNotFound:
            self.logger.error(f"错误: 未找到 {self.process_name} 进程")
        try:
            self.base_module_info = self.get_module_base_address()
        except pymem.exception.ProcessNotFound:
            self.logger.error(f"错误: 未找到基地址")
        return self.pm
    
    def disconnect(self):
        """断开连接"""
        self.unlock_all()
        
        if self.pm:
            try:
                self.pm.close_process()
                self.logger.info(f"已断开与 {self.process_name} 的连接")
            finally:
                self.pm = None
                self.base_module_info = None

    @staticmethod
    def is_system_module(module_name, module_path=""):
        """判断是否为系统模块"""
        module_lower = module_name.lower()
        
        system_prefixes = [
            'ntdll.', 'kernel32.', 'kernelbase.',
            'user32.', 'gdi32.', 'advapi32.',
            'msvcr', 'msvcp', 'vcruntime',
            'ucrtbase.', 'combase.', 'rpcrt4.',
            'ole32.', 'oleaut32.', 'shell32.',
            'shlwapi.', 'ws2_32.', 'bcrypt.',
            'crypt32.', 'sechost.', 'win32u.'
        ]
        
        system_dirs = ['\\windows\\', '\\system32\\', '\\syswow64\\']
        
        for prefix in system_prefixes:
            if module_lower.startswith(prefix):
                return True
        
        if module_path:
            path_lower = module_path.lower()
            for sys_dir in system_dirs:
                if sys_dir in path_lower:
                    return True
        
        return False
    
    @staticmethod
    def pattern_to_bytes(pattern_hex):
        """将特征码字符串转换为字节列表"""
        hex_parts = pattern_hex.replace(' ', '').upper()
        byte_list = []
        for i in range(0, len(hex_parts), 2):
            byte_str = hex_parts[i:i+2]
            if byte_str == '??':
                byte_list.append(None)
            else:
                byte_list.append(int(byte_str, 16))
        return byte_list

    @staticmethod
    def extract_bytes(hex_string, length_or_start, end=None):
        """从十六进制字符串中提取字节"""
        if not hex_string:
            return ""
        
        hex_list = hex_string.split()
        
        if end is None:
            n = length_or_start
            if n <= 0 or n > len(hex_list):
                n = len(hex_list)
            result = " ".join(hex_list[:n])
        else:
            start = length_or_start
            if start < 0 or start >= len(hex_list):
                return ""
            if end < 0 or end > len(hex_list):
                end = len(hex_list)
            result = " ".join(hex_list[start:end])
        
        return result

    @staticmethod
    def bytes_list_to_bytes(byte_list):
        """将字节列表转换为实际的 bytes 对象"""
        return bytes(b if b is not None else 0 for b in byte_list)
    
    def enum_modules_manual(self, user_only=True):
        """手动枚举进程模块"""
        try:
            hModules = (wintypes.HMODULE * MODULE_BUFFER_SIZE)()
            cbNeeded = wintypes.DWORD()
            
            if not psapi.EnumProcessModules(
                self.pm.process_handle,
                hModules,
                ctypes.sizeof(hModules),
                ctypes.byref(cbNeeded)
            ):
                err_code = ctypes.get_last_error()
                self.logger.error(f"EnumProcessModules 失败 | 错误码: {err_code}")
                return []
            
            module_count = cbNeeded.value // ctypes.sizeof(wintypes.HMODULE)
            
            modules = []
            system_modules_skipped = 0
            
            for i in range(module_count):
                modinfo = MODULEINFO()
                hModule = hModules[i]
                
                if psapi.GetModuleInformation(
                    self.pm.process_handle,
                    hModule,
                    ctypes.byref(modinfo),
                    ctypes.sizeof(modinfo)
                ):
                    module_name = ctypes.create_unicode_buffer(MAX_MODULE_NAME_LENGTH)
                    psapi.GetModuleBaseNameW(
                        self.pm.process_handle,
                        hModule,
                        module_name,
                        MAX_MODULE_NAME_LENGTH
                    )
                    
                    module_path = ctypes.create_unicode_buffer(MAX_MODULE_NAME_LENGTH)
                    psapi.GetModuleFileNameExW(
                        self.pm.process_handle,
                        hModule,
                        module_path,
                        MAX_MODULE_NAME_LENGTH
                    )
                    
                    if user_only and self.is_system_module(module_name.value, module_path.value):
                        system_modules_skipped += 1
                        continue
                    
                    modules.append({
                        'name': module_name.value,
                        'path': module_path.value,
                        'base': modinfo.lpBaseOfDll,
                        'size': modinfo.SizeOfImage
                    })
            
            if user_only:
                self.logger.info(f"\n找到 {module_count} 个模块 (已跳过 {system_modules_skipped} 个系统模块)")
                self.logger.info(f"用户模块数量: {len(modules)}")
            else:
                self.logger.info(f"\n找到 {module_count} 个模块")
            
            return modules
        
        except Exception as e:
            self.logger.error(f"枚举进程模块时发生异常: {str(e)}")
            return []

    
    def _match_pattern_at_offset(self, data, offset, pattern_list):
        """检查指定偏移是否匹配模式"""
        for i, pattern_byte in enumerate(pattern_list):
            if pattern_byte is not None and data[offset + i] != pattern_byte:
                return False
        return True
    
    def _scan_single_module(self, module, pattern_list):
        """扫描单个模块并返回匹配结果"""
        matches = []
        try:
            module_bytes = self.pm.read_bytes(module['base'], module['size'])
            
            pattern_length = len(pattern_list)
            module_length = len(module_bytes)
            
            first_byte = next((b for b in pattern_list if b is not None), None)
            if first_byte is None:
                return module_bytes, matches
                
            first_byte_positions = [i for i, b in enumerate(pattern_list) if b is not None]
            
            i = 0
            while i <= module_length - pattern_length:
                if module_bytes[i] == first_byte:
                    match = all(
                        pattern_list[pos] is None or module_bytes[i + pos] == pattern_list[pos]
                        for pos in first_byte_positions
                    )
                    if match:
                        matches.append({
                            'offset': i,
                            'bytes': module_bytes[i:i+pattern_length]
                        })
                i += 1
            
            return module_bytes, matches
        except Exception as e:
            self.logger.error(f"  ✗ 读取失败: {e}")
            return None, []
    
    def _pattern_scan_generator(self, modules, pattern_list):
        """生成器版本，懒加载匹配结果（适用于只需要第一个匹配的情况）"""
        for mod in modules:
            module_bytes, matches = self._scan_single_module(mod, pattern_list)
            if module_bytes is None:
                continue
                
            for match in matches:
                yield {
                    'module': mod,
                    'offset': match['offset'],
                    'matched_bytes': match['bytes'],
                    'address': mod['base'] + match['offset']
                }
    
    def _pattern_scan_core(self, pattern_list, find_all=True, user_only=True, return_detailed=False, base_only=False):
        """
        核心扫描方法
        Args:
            pattern_list: 模式字节列表
            find_all: 是否查找所有匹配
            user_only: 是否只扫描用户模块
            return_detailed: 是否返回详细结果
            base_only: 是否只扫描基础模块
        Returns:
            如果 return_detailed=True: 返回详细字典列表
            否则: 返回地址列表
        """
        modules = []
        if base_only:
            if self.base_module_info:
                modules = [self.base_module_info]
            else:
                self.logger.error("错误: 未获取到基础模块信息!")
                return [] if return_detailed else []
        else:
            modules = self.enum_modules_manual(user_only=user_only)
        
        if not modules:
            self.logger.error("错误: 无法枚举模块!")
            return [] if return_detailed else []
        
        self.logger.info(f"\n开始扫描 {len(modules)} 个模块...")
        if base_only:
            self.logger.info(f"范围: 基础模块 ({modules[0]['name']})")
        else:
            self.logger.info(f"范围: {'用户模块' if user_only else '所有模块'}")
        self.logger.info("\n将要扫描的模块:")
        for mod in modules:
            self.logger.info(f"  - {mod['name']} (0x{mod['base']:X})")
            if mod.get('path'):
                self.logger.info(f"    路径: {mod['path']}")

        if not find_all and not return_detailed:
            generator = self._pattern_scan_generator(modules, pattern_list)
            for match in generator:
                return [match['address']]
            return []
        
        results = []
        addresses = []
        total_matches = 0
        
        for mod in modules:
            mod_name = mod['name']
            mod_base = mod['base']
            mod_size = mod['size']
            
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"模块: {mod_name}")
            self.logger.info(f"基址: 0x{mod_base:X}")
            self.logger.info(f"大小: 0x{mod_size:X} ({mod_size:,} bytes)")
            
            module_bytes, matches = self._scan_single_module(mod, pattern_list)
            
            if module_bytes is None:
                continue
            
            matches_in_module = 0
            for match in matches:
                offset = match['offset']
                matched_bytes = match['bytes']
                addr = mod_base + offset
                matches_in_module += 1
                total_matches += 1
                
                if return_detailed:
                    result = {
                        'address': addr,
                        'bytes': matched_bytes,
                        'hex': matched_bytes.hex(' ').upper(),
                        'module': mod_name,
                        'module_base': mod_base,
                        'offset': offset
                    }
                    results.append(result)
                else:
                    addresses.append(addr)
                
                if return_detailed:
                    self.logger.info(f"  ✓ 找到匹配 #{matches_in_module}:")
                    self.logger.info(f"    地址: 0x{addr:X}")
                    self.logger.info(f"    字节: {result['hex']}")
                    self.logger.info(f"    偏移: +0x{offset:X}")
                else:
                    self.logger.info(f"  ✓ 找到匹配 #{matches_in_module}: 0x{addr:X}")
                    self.logger.info(f"    字节: {matched_bytes.hex(' ').upper()}")
                
                if not find_all:
                    break

            if matches_in_module == 0:
                self.logger.info(f"  未找到匹配")
            else:
                self.logger.info(f"  本模块共找到 {matches_in_module} 个匹配")
            
            if not find_all and (addresses or results):
                break
        
        if return_detailed:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"搜索完成! 总共找到 {len(results)} 个匹配项")
            self.logger.info(f"{'='*60}")
        else:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"搜索完成! 总共找到 {len(addresses)} 个匹配项")
            self.logger.info(f"{'='*60}")
        
        return results if return_detailed else addresses

    def _write_bytes_with_protection(self, address, replacement_bytes, original_bytes=None):
        """
        修改内存保护、写入字节、恢复保护、验证写入的内部方法
        返回字典，包含原始字节和新字节的信息
        """
        result = {'success': False, 'address': address, 'original': '', 'new': ''}
        
        if original_bytes is None:
            try:
                original_bytes = self.pm.read_bytes(address, len(replacement_bytes))
            except Exception as e:
                self.logger.error(f"✗ 读取原始字节失败: {e}")
                return result
        
        original_hex = original_bytes.hex(' ').upper()
        result['original'] = original_hex
        
        old_protect = self.change_memory_protection(address, len(replacement_bytes))
        if old_protect is None:
            self.logger.error(f"✗ 无法修改内存保护")
            return result
        
        try:
            self.pm.write_bytes(address, replacement_bytes, len(replacement_bytes))
        except Exception as e:
            self.logger.error(f"✗ 写入失败: {e}")
            self.restore_memory_protection(address, len(replacement_bytes), old_protect)
            return result
        
        self.restore_memory_protection(address, len(replacement_bytes), old_protect)
        
        try:
            verify_bytes = self.pm.read_bytes(address, len(replacement_bytes))
            new_hex = verify_bytes.hex(' ').upper()
            result['new'] = new_hex
            
            if verify_bytes == replacement_bytes:
                result['success'] = True
        except Exception as e:
            self.logger.error(f"⚠ 验证失败: {e}")
        
        return result
    
    def _wait_and_cleanup_remote_thread(self, thread_handle, shellcode_addr):
        """等待注入的代码执行完毕并清理"""
        kernel32.WaitForSingleObject(thread_handle, 5000000)
        kernel32.CloseHandle(thread_handle)
        self.logger.info("shellcode执行完毕")
        time.sleep(1)
        self.pm.free(shellcode_addr)
    
    def search(self, pattern_hex, find_all=True, user_only=True, base_only=False):
        """搜索特征码（使用十六进制字符串）"""
        pattern_list = self.pattern_to_bytes(pattern_hex)
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"搜索特征码: {pattern_hex}")
        self.logger.info(f"模式长度:   {len(pattern_list)} 字节")
        
        if base_only:
            if self.base_module_info:
                self.logger.info(f"扫描范围:   基础模块 ({self.process_name}, 0x{self.base_module_info['base']:X})")
            else:
                self.logger.info(f"扫描范围:   基础模块 (未找到模块信息)")
        else:
            self.logger.info(f"扫描范围:   {'仅用户模块' if user_only else '所有模块'}")
        self.logger.info(f"{'='*60}")
        
        return self._pattern_scan_core(
            pattern_list=pattern_list,
            find_all=find_all,
            user_only=user_only,
            return_detailed=True,
            base_only=base_only
        )
        
    def replace(self, address, replacement_hex):
        """在指定地址替换字节"""
        try:
            address = int(address, 16) if isinstance(address, str) else address
            
            replacement_list = self.pattern_to_bytes(replacement_hex)
            replacement_bytes = self.bytes_list_to_bytes(replacement_list)
            
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"替换地址: 0x{address:X}")
            self.logger.info(f"替换字节: {replacement_hex}")
            self.logger.info(f"字节长度: {len(replacement_list)}")
            self.logger.info(f"{'='*60}")
            
            try:
                original_bytes = self.pm.read_bytes(address, len(replacement_list))
                self.logger.info(f"原始字节: {original_bytes.hex(' ').upper()}")
            except Exception as e:
                self.logger.error(f"✗ 读取原始字节失败: {e}")
                return {'address': address, 'original': '', 'new': ''}
            
            result = self._write_bytes_with_protection(address, replacement_bytes, original_bytes)
            
            if result['success']:
                self.logger.info(f"✓ 替换成功并验证通过!")
            else:
                self.logger.error(f"✗ 替换失败")
            
            return {'address': address, 'original': result['original'], 'new': result['new']}
                
        except Exception as e:
            self.logger.error(f"✗ 替换异常: {e}")
            return {'address': address, 'original': '', 'new': ''}

    def search_and_replace(self, pattern_hex, replacement_hex, replace_all=False, 
                           user_only=True, base_only=False):
        """搜索特征码并替换"""
        pattern_list = self.pattern_to_bytes(pattern_hex)
        replacement_list = self.pattern_to_bytes(replacement_hex)
        
        if len(replacement_list) != len(pattern_list):
            self.logger.error(f"错误: 特征码长度({len(pattern_list)})与替换码长度({len(replacement_list)})不匹配")
            return {"success_count": 0, "data": [], "errors": ["长度不匹配"]}
        
        replacement_bytes = self.bytes_list_to_bytes(replacement_list)
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"搜索特征码: {pattern_hex}")
        self.logger.info(f"替换为:     {replacement_hex}")
        self.logger.info(f"模式长度:   {len(pattern_list)} 字节")
        
        if base_only:
            if self.base_module_info:
                self.logger.info(f"扫描范围:   基础模块 ({self.process_name}, 0x{self.base_module_info['base']:X})")
            else:
                self.logger.info(f"扫描范围:   基础模块 (未找到模块信息)")
        else:
            self.logger.info(f"扫描范围:   {'仅用户模块' if user_only else '所有模块'}")
        self.logger.info(f"{'='*60}")
        
        results = self._pattern_scan_core(
            pattern_list=pattern_list,
            find_all=replace_all,
            user_only=user_only,
            return_detailed=True,
            base_only=base_only
        )
        
        if not results:
            self.logger.error("\n❌ 未找到任何匹配项！")
            return {"success_count": 0, "data": [], "errors": ["未找到匹配项"]}
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"总共找到 {len(results)} 个匹配项，开始替换...")
        self.logger.info(f"{'='*60}")
        
        result = {
            "success_count": 0,
            "data": [],
            "errors": []
        }
        
        for i, match in enumerate(results):
            addr = match['address']
            mod_name = match['module']
            mod_base = match['module_base']
            offset = match['offset']
            original_hex = match['hex']
            
            try:
                self.logger.info(f"\n[{i+1}/{len(results)}] 地址: 0x{addr:X}")
                self.logger.info(f"  模块: {mod_name} (0x{mod_base:X})")
                self.logger.info(f"  偏移: 0x{offset:X}")
                self.logger.info(f"  原始: {original_hex}")
                
                replace_result = self._write_bytes_with_protection(addr, replacement_bytes)
                
                if replace_result['new']:
                    self.logger.info(f"  新值: {replace_result['new']}")
                
                if replace_result['success']:
                    self.logger.info(f"  ✓ 替换成功!")
                    result['success_count'] += 1
                    result['data'].append({
                        'address': addr,
                        'module': mod_name,
                        'module_base': mod_base,
                        'offset': offset,
                        'original': original_hex,
                        'new': replace_result['new']
                    })
                else:
                    error_msg = f"验证失败: 地址 0x{addr:X}"
                    result["errors"].append(error_msg)
                    self.logger.error(f"  ✗ {error_msg}")
                    
            except Exception as e:
                error_msg = f"替换异常: 地址 0x{addr:X}, 错误: {e}"
                result["errors"].append(error_msg)
                self.logger.error(f"  ✗ {error_msg}")
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"替换完成! 成功: {result['success_count']}/{len(results)}")
        if result['errors']:
            self.logger.error(f"失败: {len(result['errors'])}")
        self.logger.info(f"{'='*60}")
        
        return result

    def inject_shellcode(self, shellcode):
        """代码注入"""
        shellcode_length = len(shellcode)
        shellcode_addr = self.pm.allocate(shellcode_length)
        self.change_memory_protection(shellcode_addr, shellcode_length)
        self.write_value(shellcode_addr, shellcode, "bytes")
        self.logger.info(f"写入sheellcode成功，地址：0x{shellcode_addr:X}，长度：{shellcode_length}")
        thread_h = kernel32.CreateRemoteThread(
            self.pm.process_handle,
            None,
            0,
            ctypes.c_void_p(shellcode_addr),
            None,
            0,
            None
        )
        if thread_h:
            cleanup_thread = threading.Thread(
                target=self._wait_and_cleanup_remote_thread,
                args=(thread_h, shellcode_addr),
                daemon=True
            )
            cleanup_thread.start()
        else:
            error_code = kernel32.GetLastError()
            self.logger.error(f"✗ 创建远程线程失败，错误代码: {error_code}")
        
    def change_memory_protection(self, address, size):
        """修改内存页保护属性"""
        old_protect = wintypes.DWORD()
        addr_ptr = ctypes.c_void_p(address)

        result = kernel32.VirtualProtectEx(
            self.pm.process_handle,
            addr_ptr,
            ctypes.c_size_t(size),
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect)
        )

        if result == 0:
            return
        else:
            self.logger.info(f"内存权限修改成功，原权限: 0x{old_protect.value:X}")
            return old_protect

    def restore_memory_protection(self, address, size, protect):
        """恢复内存保护属性"""
        try:
            old_protect = wintypes.DWORD()
            addr_ptr = ctypes.c_void_p(address)
            
            result = kernel32.VirtualProtectEx(
                self.pm.process_handle,
                addr_ptr,
                ctypes.c_size_t(size),
                protect,
                ctypes.byref(old_protect)
            )
            
            if result == 0:
                err_code = ctypes.get_last_error()
                raise RuntimeError(f"API调用失败，错误码: {err_code}")
        except Exception as e:
            self.logger.error(f"  恢复保护失败: {e}")
            
    def get_module_base_address(self):
        """获取模块基地址"""
        if self.pm:
            try:
                module = pymem.process.module_from_name(self.pm.process_handle, self.process_name)
                return {
                    'base': module.lpBaseOfDll,
                    'size': module.SizeOfImage,
                    'name': self.process_name
                }
            except Exception as e:
                self.logger.error(f"获取模块基地址失败: {e}")
                return None

    def calculate_pointer_chain(self, base_offset, offsets):
        """计算指针链地址"""
        if not self.pm or self.base_module_info is None:
            raise RuntimeError("未连接到进程或未获取基址")
        
        if not offsets:
            return self.base_module_info['base'] + base_offset
        
        try:
            current_address = self.base_module_info['base'] + base_offset
            for i, offset in enumerate(offsets):
                try:
                    current_address = self.pm.read_int(current_address) + offset
                except pymem.exception.MemoryReadError:
                    raise ValueError(f"指针链第 {i+1} 层解引用失败 (地址: 0x{current_address:X})")
            return current_address
        except pymem.exception.MemoryReadError as e:
            raise ValueError(f"指针链计算失败: {e}")
    
    def write_value(self, address, value, data_type='int'):
        """写入内存值"""
        if not self.pm:
            return False
        
        try:
            if data_type == 'int':
                self.pm.write_int(address, int(value))
            elif data_type == 'float':
                self.pm.write_float(address, float(value))
            elif data_type == 'double':
                self.pm.write_double(address, float(value))
            elif data_type == 'bool':
                self.pm.write_bool(address, bool(value))
            elif data_type == 'bytes':
                self.pm.write_bytes(address, bytes(value), len(bytes(value)))
            else:
                self.logger.error(f"不支持的数据类型: {data_type}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"写入内存失败: {e}")
            return False
    
    def read_value(self, address, data_type='int'):
        """读取内存值"""
        if not self.pm:
            return None
        
        try:
            if data_type == 'int':
                return self.pm.read_int(address)
            elif data_type == 'float':
                return self.pm.read_float(address)
            elif data_type == 'double':
                return self.pm.read_double(address)
            elif data_type == 'bool':
                return self.pm.read_bool(address)
            elif data_type == 'bytes':
                return self.pm.read_bytes(address, 4)
            elif data_type == 'byte':
                return self.pm.read_bytes(address, 1)
            else:
                self.logger.error(f"不支持的数据类型: {data_type}")
                return None
        except Exception as e:
            self.logger.error(f"读取内存失败: {e}")
            return None

    def lock_value(self, address, value, data_type='int', interval=0.05, lock_id=None):
        """
        锁定内存值
        """
        if not self.pm:
            self.logger.error("未连接到进程")
            return None
            
        address = int(address, 16) if isinstance(address, str) else address
        
        with self._lock_threads_lock:
            if lock_id is None:
                self._lock_counter += 1
                lock_id = f"lock_{self._lock_counter}"
            
            if lock_id in self._lock_threads:
                self.logger.warning(f"锁定ID '{lock_id}' 已存在，将先解锁旧任务")
                self._unlock_value_internal(lock_id)
        
        stop_event = threading.Event()
        
        def lock_thread():
            self.logger.info(f"[{lock_id}] 开始锁定 0x{address:X} = {value} ({data_type})")
            write_count = 0
            error_count = 0
            
            while not stop_event.is_set():
                try:
                    success = self.write_value(address, value, data_type)
                    if success:
                        write_count += 1
                    else:
                        error_count += 1
                        if error_count > 10:
                            self.logger.error(f"[{lock_id}] 连续写入失败，停止锁定")
                            break
                except Exception as e:
                    error_count += 1
                    if error_count <= 3:
                        self.logger.error(f"[{lock_id}] 写入异常: {e}")
                    if error_count > 10:
                        break
                
                time.sleep(interval)
            
            self.logger.info(f"[{lock_id}] 停止锁定 (总写入: {write_count}, 错误: {error_count})")
        
        thread = threading.Thread(target=lock_thread, daemon=True, name=f"MemLock-{lock_id}")
        thread.start()
        
        with self._lock_threads_lock:
            self._lock_threads[lock_id] = {
                'thread': thread,
                'stop_event': stop_event,
                'info': {
                    'address': address,
                    'value': value,
                    'data_type': data_type,
                    'interval': interval,
                    'start_time': time.time()
                }
            }
        
        return lock_id
    
    def unlock_value(self, lock_id):
        """
        解锁指定的内存值
        """
        with self._lock_threads_lock:
            return self._unlock_value_internal(lock_id)
    
    def _unlock_value_internal(self, lock_id):
        """内部解锁方法"""
        if lock_id not in self._lock_threads:
            self.logger.warning(f"锁定ID '{lock_id}' 不存在")
            return False
        
        lock_info = self._lock_threads[lock_id]
        lock_info['stop_event'].set()
        lock_info['thread'].join(timeout=1.0)
        
        del self._lock_threads[lock_id]
        self.logger.info(f"已解锁 '{lock_id}'")
        return True
    
    def unlock_all(self):
        """解锁所有内存值"""
        with self._lock_threads_lock:
            lock_ids = list(self._lock_threads.keys())
        
        count = 0
        for lock_id in lock_ids:
            if self.unlock_value(lock_id):
                count += 1
        
        self.logger.info(f"已解锁所有任务 (共 {count} 个)")
        return count
    
    def get_active_locks(self):
        """ 获取所有活跃的锁定任务信息 """
        with self._lock_threads_lock:
            return {
                lock_id: data['info'].copy() 
                for lock_id, data in self._lock_threads.items()
            }

    def get_hwnds(self):
        """获取目标进程的所有窗口句柄及详细信息"""
        windows_info = []  # 改为存储窗口信息字典的列表
        target_pid = self.pm.process_id
        
        def callback(hwnd, extra):
            if user32.IsWindowVisible(hwnd):
                window_pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
                
                if window_pid.value == target_pid:
                    # 获取窗口标题
                    length = user32.GetWindowTextLengthW(hwnd) + 1
                    title_buffer = ctypes.create_unicode_buffer(length)
                    user32.GetWindowTextW(hwnd, title_buffer, length)
                    window_title = title_buffer.value
                    
                    # 获取窗口类名
                    class_buffer = ctypes.create_unicode_buffer(256)
                    user32.GetClassNameW(hwnd, class_buffer, 256)
                    window_class = class_buffer.value
                    
                    # 获取窗口位置和大小
                    rect = wintypes.RECT()
                    user32.GetWindowRect(hwnd, ctypes.byref(rect))
                    
                    # 检查窗口是否最小化/最大化
                    is_iconic = user32.IsIconic(hwnd)
                    is_zoomed = user32.IsZoomed(hwnd)
                    
                    # 检查窗口是否可用
                    is_enabled = user32.IsWindowEnabled(hwnd)
                    
                    # 获取父窗口
                    parent_hwnd = user32.GetParent(hwnd)
                    
                    # 创建窗口信息字典
                    window_info = {
                        'hwnd': hwnd,
                        'pid': window_pid.value,
                        'title': window_title,
                        'class_name': window_class,
                        'rect': {
                            'left': rect.left,
                            'top': rect.top,
                            'right': rect.right,
                            'bottom': rect.bottom,
                            'width': rect.right - rect.left,
                            'height': rect.bottom - rect.top
                        },
                        'position': (rect.left, rect.top),
                        'size': (rect.right - rect.left, rect.bottom - rect.top),
                        'is_visible': True,
                        'is_enabled': bool(is_enabled),
                        'is_minimized': bool(is_iconic),
                        'is_maximized': bool(is_zoomed),
                        'parent_hwnd': parent_hwnd,
                    }
                    
                    windows_info.append(window_info)
            return True
        
        enum_func = EnumWindowsProc(callback)
        user32.EnumWindows(enum_func, 0)
        
        return windows_info
        
    def get_winapi_func_addr(self,dll_name, func_name):
        """ 获取Windows API函数内存地址 """
        dll_obj = None
        try:
            global_vars = sys._getframe(1).f_globals
            if dll_name in global_vars and isinstance(global_vars[dll_name], ctypes.WinDLL):
                dll_obj = global_vars[dll_name]

            if dll_obj is None:
                dll_obj = ctypes.WinDLL(dll_name)

            func_obj = getattr(dll_obj, func_name)
            func_address = ctypes.cast(func_obj, ctypes.c_void_p).value
            return func_address

        except AttributeError:
            print(f"错误: {dll_name}.{func_name} 函数不存在")
            return None
        except Exception as e:
            print(f"错误: 获取 {dll_name}.{func_name} 地址失败: {str(e)}")
            return None
