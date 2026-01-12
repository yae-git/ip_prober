import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import ipaddress
import subprocess
import socket
import threading
import time
from openpyxl import Workbook
import os
import re
import sys
import struct

class IPProber:
    def __init__(self, root):
        self.root = root
        self.root.title("IP探测工具 - 资产识别")
        self.root.geometry("800x600")
        
        # 设置界面样式
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # 扫描结果
        self.scan_results = []
        
        # 运行状态
        self.running = False
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 输入区域 - 支持拉伸
        self.input_frame = ttk.LabelFrame(self.main_frame, text="扫描设置", padding="10")
        self.input_frame.pack(fill=tk.X, pady=5)
        
        # 配置输入框架的grid权重
        self.input_frame.grid_columnconfigure(1, weight=1)  # IP输入框自适应
        
        # IP地址/段输入
        ttk.Label(self.input_frame, text="IP地址或地址段:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(self.input_frame)
        self.ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)  # 水平拉伸
        self.ip_entry.insert(0, "192.168.1.1-20")  # 默认值，方便测试
        
        # 线程数设置
        ttk.Label(self.input_frame, text="线程数:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.thread_var = tk.StringVar(value="20")  # 默认20线程，提高扫描速度
        self.thread_entry = ttk.Entry(self.input_frame, width=10, textvariable=self.thread_var)
        self.thread_entry.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        
        # 扫描按钮
        self.scan_button = ttk.Button(self.input_frame, text="开始探测", command=self.start_scan)
        self.scan_button.grid(row=0, column=4, padx=10, pady=5)
        
        # 停止按钮
        self.stop_button = ttk.Button(self.input_frame, text="停止探测", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=5, padx=10, pady=5)
        
        # 导出按钮
        self.export_button = ttk.Button(self.input_frame, text="导出结果", command=self.export_to_excel, state=tk.DISABLED)
        self.export_button.grid(row=0, column=6, padx=10, pady=5)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # 结果显示区域
        self.result_frame = ttk.LabelFrame(self.main_frame, text="探测结果", padding="10")
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 结果表格
        columns = ("IP地址", "状态", "MAC地址")
        self.result_tree = ttk.Treeview(self.result_frame, columns=columns, show="headings")
        
        # 设置列配置 - 支持自适应宽度
        column_config = {
            "IP地址": {"text": "IP地址", "width": 150, "stretch": True},
            "状态": {"text": "状态", "width": 100, "stretch": True},
            "MAC地址": {"text": "MAC地址", "width": 180, "stretch": True}
        }
        
        for col in columns:
            self.result_tree.heading(col, text=column_config[col]["text"])
            # 配置列宽和拉伸属性
            self.result_tree.column(
                col, 
                width=column_config[col]["width"],
                stretch=column_config[col]["stretch"]
            )
        
        # 垂直滚动条
        self.tree_scroll_y = ttk.Scrollbar(self.result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=self.tree_scroll_y.set)
        
        # 水平滚动条
        self.tree_scroll_x = ttk.Scrollbar(self.result_frame, orient=tk.HORIZONTAL, command=self.result_tree.xview)
        self.result_tree.configure(xscrollcommand=self.tree_scroll_x.set)
        
        # 布局
        self.result_tree.grid(row=0, column=0, sticky=tk.NSEW)
        self.tree_scroll_y.grid(row=0, column=1, sticky=tk.NS)
        self.tree_scroll_x.grid(row=1, column=0, sticky=tk.EW)
        
        # 设置grid权重
        self.result_frame.grid_rowconfigure(0, weight=1)
        self.result_frame.grid_columnconfigure(0, weight=1)
        
        # 为列添加排序功能
        for col in columns:
            self.result_tree.heading(col, text=column_config[col]["text"], command=lambda _col=col: self._treeview_sort_column(_col, False))
        
        # 日志区域
        self.log_frame = ttk.LabelFrame(self.main_frame, text="探测日志", padding="10")
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 移除固定高度，让日志框自适应窗口大小
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, anchor=tk.CENTER)
        
        # 配置窗口大小变化事件
        self.root.bind('<Configure>', self._on_window_resize)
    
    def log(self, message):
        """记录日志"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        self.log_text.insert(tk.END, f"{timestamp} - {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def parse_ip_input(self, ip_input):
        """解析IP输入，支持单个IP、IP范围、CIDR"""
        ips = []
        try:
            if '-' in ip_input:
                # 处理IP范围
                start_ip, end_ip = ip_input.split('-')
                if '.' in end_ip:
                    # 完整IP范围，如192.168.1.1-192.168.1.10
                    start = ipaddress.IPv4Address(start_ip.strip())
                    end = ipaddress.IPv4Address(end_ip.strip())
                    for ip_int in range(int(start), int(end) + 1):
                        ips.append(str(ipaddress.IPv4Address(ip_int)))
                else:
                    # 同网段IP范围，如192.168.1.1-10
                    parts = start_ip.strip().split('.')
                    base = '.'.join(parts[:-1])
                    start_num = int(parts[-1])
                    end_num = int(end_ip.strip())
                    for num in range(start_num, end_num + 1):
                        ips.append(f"{base}.{num}")
            elif '/' in ip_input:
                # 处理CIDR，如192.168.1.0/24
                network = ipaddress.IPv4Network(ip_input.strip(), strict=False)
                for ip in network.hosts():
                    ips.append(str(ip))
            else:
                # 单个IP
                ip = ipaddress.IPv4Address(ip_input.strip())
                ips.append(str(ip))
            return ips
        except Exception as e:
            self.log(f"IP解析错误: {e}")
            messagebox.showerror("错误", f"IP地址格式错误: {e}")
            return []
    
    def arp_scan(self, ip):
        """使用ARP扫描检测IP是否在线并获取MAC地址"""
        try:
            # 使用arp命令直接获取MAC地址，同时判断是否在线
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            # 正则匹配MAC地址
            mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
            match = re.search(mac_pattern, result.stdout)
            if match:
                return True, match.group(0).upper()
        except Exception:
            pass
        
        # 如果ARP缓存中没有，尝试使用arping命令（如果系统有安装）
        try:
            result = subprocess.run(
                ["arping", "-c", "1", "-w", "1", ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            if "reply" in result.stdout.lower():
                # 再次获取ARP缓存
                arp_result = subprocess.run(
                    ["arp", "-a", ip],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                match = re.search(mac_pattern, arp_result.stdout)
                if match:
                    return True, match.group(0).upper()
        except Exception:
            pass
        
        return False, ""
    
    def tcp_syn_scan(self, ip, port=80):
        """使用TCP SYN扫描检测IP是否在线"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # 使用connect_ex替代connect，非阻塞连接
            result = sock.connect_ex((ip, port))
            sock.close()
            
            # 如果端口开放或被过滤，说明主机在线
            return result == 0 or result == 111  # 111是Connection refused，说明主机在线但端口关闭
        except Exception:
            return False
    
    def get_mac_address(self, ip):
        """获取IP对应的MAC地址"""
        try:
            # 使用arp命令获取MAC地址
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            # 正则匹配MAC地址
            mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
            match = re.search(mac_pattern, result.stdout)
            if match:
                return match.group(0).upper()
        except Exception:
            pass
        return ""
    
    def ping_ip(self, ip):
        """使用ping检测IP是否在线"""
        try:
            # Windows系统使用ping命令
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "1000", ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            return "TTL=" in result.stdout
        except Exception:
            return False
    
    def scan_ip(self, ip):
        """扫描单个IP - 结合ARP扫描、TCP SYN扫描和ping扫描"""
        is_online = False
        mac_address = ""
        
        # 1. 优先使用ARP扫描，效率高且能获取MAC地址
        arp_online, mac = self.arp_scan(ip)
        if arp_online:
            is_online = True
            mac_address = mac
        else:
            # 2. ARP扫描失败，尝试ping扫描，防止丢包情况
            if self.ping_ip(ip):
                is_online = True
                mac_address = self.get_mac_address(ip)
            else:
                # 3. ping扫描失败，尝试TCP SYN扫描常用端口
                common_ports = [80, 443, 22, 23, 3389, 21]
                for port in common_ports:
                    if self.tcp_syn_scan(ip, port):
                        is_online = True
                        # 获取MAC地址（可能为空）
                        mac_address = self.get_mac_address(ip)
                        break
        
        # 确定状态
        if is_online:
            status = "在线"
        else:
            status = "离线"
            # 尝试获取离线IP的MAC地址
            if not mac_address:
                mac_address = self.get_mac_address(ip)
            # 如果没有MAC地址，标记为未使用
            if not mac_address:
                status = "未使用"
        
        return ip, status, mac_address
    
    def scan_thread(self, ip_list, thread_id, total_threads):
        """扫描线程"""
        for i, ip in enumerate(ip_list):
            if not self.running:
                break
                
            try:
                result = self.scan_ip(ip)
                
                # 使用线程安全的方式更新GUI和结果
                self.root.after(0, self._update_result_safe, result, thread_id, len(ip_list), i, total_threads)
            except Exception as e:
                self.root.after(0, self.log, f"扫描IP {ip} 时出错: {e}")
    
    def _update_result_safe(self, result, thread_id, thread_ip_count, index, total_threads):
        """线程安全的结果更新方法"""
        # 记录结果
        self.scan_results.append(result)
        # 更新结果树
        self.update_result_tree(result)
        # 更新进度
        progress = ((thread_id * thread_ip_count + index + 1) / self.total_ips) * 100
        self.progress_var.set(progress)
    
    def update_result_tree(self, result):
        """更新结果表格"""
        self.result_tree.insert("", tk.END, values=result)
    
    def _treeview_sort_column(self, col, reverse):
        """Treeview列排序函数"""
        # 获取所有行
        data = [(self.result_tree.set(child, col), child) for child in self.result_tree.get_children('')]
        
        # 自定义排序逻辑
        if col == "IP地址":
            # IP地址排序：将IP转换为整数进行比较
            def ip_to_int(ip):
                parts = list(map(int, ip.split('.')))
                return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            
            data.sort(key=lambda x: ip_to_int(x[0]), reverse=reverse)
        elif col == "状态":
            # 状态排序：按照在线 > 离线 > 未使用的顺序
            status_priority = {"在线": 0, "离线": 1, "未使用": 2}
            data.sort(key=lambda x: status_priority.get(x[0], 3), reverse=reverse)
        else:
            # 其他列使用默认字符串排序
            data.sort(reverse=reverse)
        
        # 重新插入排序后的数据
        for index, (val, child) in enumerate(data):
            self.result_tree.move(child, '', index)
        
        # 切换排序方向
        self.result_tree.heading(col, command=lambda _col=col: self._treeview_sort_column(_col, not reverse))
    
    def _on_window_resize(self, event):
        """窗口大小变化事件处理"""
        # 刷新界面，确保所有元素正确自适应
        self.root.update_idletasks()
    
    def stop_scan(self):
        """停止扫描"""
        self.running = False
        self.log("正在停止探测...")
        self.stop_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.NORMAL)
    
    def start_scan(self):
        """开始扫描"""
        # 初始化状态
        self.running = True
        
        # 更新按钮状态
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)
        
        # 清空之前的结果
        self.result_tree.delete(*self.result_tree.get_children())
        self.scan_results.clear()
        
        # 重置进度条
        self.progress_var.set(0)
        
        # 获取输入
        ip_input = self.ip_entry.get().strip()
        if not ip_input:
            messagebox.showerror("错误", "请输入IP地址或地址段")
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            return
        
        # 解析IP列表
        ip_list = self.parse_ip_input(ip_input)
        if not ip_list:
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            return
        
        self.total_ips = len(ip_list)
        self.log(f"开始探测 {self.total_ips} 个IP地址")
        
        # 获取线程数
        try:
            thread_count = int(self.thread_var.get())
            # 限制线程数范围（1-100）
            thread_count = max(1, min(thread_count, 100))
        except Exception as e:
            self.log(f"线程数设置错误: {e}，使用默认值20")
            thread_count = 20
        
        # 分配IP列表给多个线程
        threads = []
        ips_per_thread = len(ip_list) // thread_count
        
        for i in range(thread_count):
            start = i * ips_per_thread
            end = (i + 1) * ips_per_thread if i < thread_count - 1 else len(ip_list)
            thread_ips = ip_list[start:end]
            
            if thread_ips:
                thread = threading.Thread(target=self.scan_thread, args=(thread_ips, i, thread_count))
                threads.append(thread)
                thread.start()
        
        # 等待扫描完成
        def wait_for_scan():
            # 等待所有线程完成
            for thread in threads:
                thread.join()
            
            self.running = False
            self.log(f"探测完成，共发现 {len(self.scan_results)} 个IP")
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.export_button.config(state=tk.NORMAL if self.scan_results else tk.DISABLED)
            self.progress_var.set(100)
        
        # 启动等待线程
        threading.Thread(target=wait_for_scan).start()
    
    def _get_safe_filename(self, ip_input):
        """将IP输入转换为安全的文件名"""
        # 替换特殊字符
        safe_name = re.sub(r'[\\/:*?\"<>|]', '_', ip_input)
        # 限制长度
        if len(safe_name) > 50:
            safe_name = safe_name[:50]
        # 去除首尾空白
        safe_name = safe_name.strip()
        # 如果为空，使用默认名称
        if not safe_name:
            safe_name = "ip_probe_result"
        return safe_name
    
    def export_to_excel(self):
        """导出结果到Excel - 使用扫描的IP段作为文件名"""
        if not self.scan_results:
            messagebox.showwarning("警告", "没有探测结果可以导出")
            return
        
        try:
            # 获取IP输入
            ip_input = self.ip_entry.get().strip()
            # 生成安全的文件名
            safe_filename = self._get_safe_filename(ip_input)
            
            # 创建工作簿
            wb = Workbook()
            ws = wb.active
            ws.title = "IP探测结果"
            
            # 写入表头
            headers = ["IP地址", "状态", "MAC地址"]
            ws.append(headers)
            
            # 写入数据
            for result in self.scan_results:
                ws.append(result)
            
            # 保存文件 - 使用IP段作为文件名
            filename = f"{safe_filename}_probe_result.xlsx"
            wb.save(filename)
            
            self.log(f"结果已导出到: {filename}")
            messagebox.showinfo("成功", f"结果已导出到: {os.path.abspath(filename)}")
        except Exception as e:
            self.log(f"导出失败: {e}")
            messagebox.showerror("错误", f"导出失败: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = IPProber(root)
    root.mainloop()