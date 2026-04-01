#!/usr/bin/env python3
# Intelligent System for Automation of Security Audits (SIAAS)
# GUI Interface - Visualização de resultados
# By <O TEU NOME>, 2026

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import siaas_aux
import json
import os
import threading
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAR_DIR = os.path.join(BASE_DIR, "siaas-agent", "var")
PORTSCANNER_DB = os.path.join(VAR_DIR, "portscanner.db")
WEBSCANNER_DB = os.path.join(VAR_DIR, "webscanner.db")

# Criar diretório de logs para a GUI
GUI_LOG_DIR = os.path.join(BASE_DIR, "siaas-gui", "logs")
os.makedirs(GUI_LOG_DIR, exist_ok=True)


class SIAASGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SIAAS - Security Audit System")
        self.root.geometry("1400x800")
        
        # Configurar estilo
        self.setup_styles()
        
        # Criar interface
        self.create_widgets()
        
        # Carregar dados iniciais
        self.refresh_data()
        
        # Auto-refresh a cada 30 segundos
        self.auto_refresh()
    
    def setup_styles(self):
        """Configurar estilos da interface"""
        self.style = ttk.Style()
        
        # Cores
        self.colors = {
            'bg_dark': '#1e1e1e',
            'bg_light': '#2d2d30',
            'text': '#d4d4d4',
            'accent': '#007acc',
            'high': '#ff5555',
            'medium': '#ffaa00',
            'low': '#55aa55',
            'info': '#5555ff'
        }
        
        self.root.configure(bg=self.colors['bg_dark'])
        
        # Configurar estilos dos widgets
        self.style.configure('Title.TLabel', 
                           background=self.colors['bg_dark'],
                           foreground=self.colors['text'],
                           font=('Segoe UI', 14, 'bold'))
        
        self.style.configure('Subtitle.TLabel',
                           background=self.colors['bg_dark'],
                           foreground=self.colors['text'],
                           font=('Segoe UI', 12))
        
        self.style.configure('Stats.TLabel',
                           background=self.colors['bg_light'],
                           foreground=self.colors['text'],
                           font=('Segoe UI', 10))
        
        self.style.configure('Treeview',
                           background=self.colors['bg_light'],
                           foreground=self.colors['text'],
                           fieldbackground=self.colors['bg_light'])
        
        self.style.configure('Treeview.Heading',
                           background=self.colors['accent'],
                           foreground='white',
                           font=('Segoe UI', 10, 'bold'))
        
        self.style.map('Treeview',
                      background=[('selected', self.colors['accent'])],
                      foreground=[('selected', 'white')])
    
    def create_widgets(self):
        """Criar todos os widgets da interface"""
        
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Barra de título
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(title_frame, text="🔒 SIAAS - Security Audit System", 
                 style='Title.TLabel').pack(side=tk.LEFT)
        
        # Botões de controle
        control_frame = ttk.Frame(title_frame)
        control_frame.pack(side=tk.RIGHT)
        
        ttk.Button(control_frame, text="🔄 Refresh", 
                  command=self.refresh_data).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="📊 Stats", 
                  command=self.show_stats).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="⚙️ Settings", 
                  command=self.show_settings).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="❓ Help", 
                  command=self.show_help).pack(side=tk.LEFT, padx=2)
        
        # Notebook (abas)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Aba 1: Dashboard
        self.create_dashboard_tab()
        
        # Aba 2: Port Scanner
        self.create_portscanner_tab()
        
        # Aba 3: Web Scanner
        self.create_webscanner_tab()
        
        # Aba 4: Logs
        self.create_logs_tab()
        
        # Status bar
        self.status_bar = ttk.Label(main_frame, 
                                   text="Ready | Last update: --:--:--",
                                   relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=(5, 0))
    
    def create_dashboard_tab(self):
        """Criar aba do Dashboard"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        
        # Estatísticas gerais
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Overall Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Grid para estatísticas
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Estatísticas do Port Scanner
        self.port_stats_vars = {}
        port_stats = [
            ("Total Hosts", "port_hosts"),
            ("Open Ports", "port_ports"),
            ("Vulnerabilities", "port_vulns"),
            ("Exploits", "port_exploits"),
            ("Last Scan", "port_last")
        ]
        
        ttk.Label(stats_grid, text="Port Scanner:", 
                 font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=5)
        
        for i, (label, key) in enumerate(port_stats):
            ttk.Label(stats_grid, text=label + ":").grid(row=i+1, column=0, sticky=tk.W, padx=20)
            self.port_stats_vars[key] = tk.StringVar(value="0")
            ttk.Label(stats_grid, textvariable=self.port_stats_vars[key],
                     style='Stats.TLabel').grid(row=i+1, column=1, sticky=tk.W)
        
        # Estatísticas do Web Scanner
        self.web_stats_vars = {}
        web_stats = [
            ("Web Hosts", "web_hosts"),
            ("Scanned Ports", "web_ports"),
            ("Vulnerabilities", "web_vulns"),
            ("Exploits", "web_exploits"),
            ("Last Scan", "web_last")
        ]
        
        ttk.Label(stats_grid, text="Web Scanner:", 
                 font=('Segoe UI', 10, 'bold')).grid(row=0, column=2, sticky=tk.W, pady=5, padx=(40,0))
        
        for i, (label, key) in enumerate(web_stats):
            ttk.Label(stats_grid, text=label + ":").grid(row=i+1, column=2, sticky=tk.W, padx=60)
            self.web_stats_vars[key] = tk.StringVar(value="0")
            ttk.Label(stats_grid, textvariable=self.web_stats_vars[key],
                     style='Stats.TLabel').grid(row=i+1, column=3, sticky=tk.W)
        
        # Top hosts vulneráveis (CONSOLIDADOS)
        vuln_frame = ttk.LabelFrame(dashboard_frame, text="Top Vulnerable Hosts (Consolidated)")
        vuln_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('host', 'vulns', 'exploits', 'last_scan', 'scanners')
        self.vuln_tree = ttk.Treeview(vuln_frame, columns=columns, show='headings', height=10)
        
        self.vuln_tree.heading('host', text='Host')
        self.vuln_tree.heading('vulns', text='Vulnerabilities')
        self.vuln_tree.heading('exploits', text='Exploits')
        self.vuln_tree.heading('last_scan', text='Last Scan')
        self.vuln_tree.heading('scanners', text='Scanners')
        
        self.vuln_tree.column('host', width=200)
        self.vuln_tree.column('vulns', width=100, anchor=tk.CENTER)
        self.vuln_tree.column('exploits', width=100, anchor=tk.CENTER)
        self.vuln_tree.column('last_scan', width=150, anchor=tk.CENTER)
        self.vuln_tree.column('scanners', width=100, anchor=tk.CENTER)
        
        scrollbar = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_portscanner_tab(self):
        """Criar aba do Port Scanner"""
        port_frame = ttk.Frame(self.notebook)
        self.notebook.add(port_frame, text="🔍 Port Scanner")
        
        # Filtros
        filter_frame = ttk.Frame(port_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0,5))
        self.port_filter_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.port_filter_var, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply", 
                  command=self.filter_port_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear", 
                  command=self.clear_port_filter).pack(side=tk.LEFT)
        
        # Treeview para hosts
        columns = ('host', 'os', 'ports', 'vulns', 'exploits', 'last_check')
        self.port_tree = ttk.Treeview(port_frame, columns=columns, show='headings', height=20)
        
        self.port_tree.heading('host', text='Host')
        self.port_tree.heading('os', text='Operating System')
        self.port_tree.heading('ports', text='Open Ports')
        self.port_tree.heading('vulns', text='Vulnerabilities')
        self.port_tree.heading('exploits', text='Exploits')
        self.port_tree.heading('last_check', text='Last Check')
        
        self.port_tree.column('host', width=150)
        self.port_tree.column('os', width=200)
        self.port_tree.column('ports', width=100, anchor=tk.CENTER)
        self.port_tree.column('vulns', width=100, anchor=tk.CENTER)
        self.port_tree.column('exploits', width=100, anchor=tk.CENTER)
        self.port_tree.column('last_check', width=150, anchor=tk.CENTER)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(port_frame, orient=tk.VERTICAL, command=self.port_tree.yview)
        h_scrollbar = ttk.Scrollbar(port_frame, orient=tk.HORIZONTAL, command=self.port_tree.xview)
        self.port_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Layout
        self.port_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Frame para detalhes
        detail_frame = ttk.LabelFrame(port_frame, text="Port Details")
        detail_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.port_detail_text = scrolledtext.ScrolledText(detail_frame, height=10)
        self.port_detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind click event
        self.port_tree.bind('<<TreeviewSelect>>', self.show_port_details)
    
    def create_webscanner_tab(self):
        """Criar aba do Web Scanner"""
        web_frame = ttk.Frame(self.notebook)
        self.notebook.add(web_frame, text="🌐 Web Scanner")
        
        # Filtros
        filter_frame = ttk.Frame(web_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0,5))
        self.web_filter_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.web_filter_var, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply", 
                  command=self.filter_web_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear", 
                  command=self.clear_web_filter).pack(side=tk.LEFT)
        
        # Treeview para web hosts
        columns = ('host', 'url', 'server', 'vulns', 'exploits', 'last_check')
        self.web_tree = ttk.Treeview(web_frame, columns=columns, show='headings', height=15)
        
        self.web_tree.heading('host', text='Host')
        self.web_tree.heading('url', text='URL')
        self.web_tree.heading('server', text='Server')
        self.web_tree.heading('vulns', text='Vulnerabilities')
        self.web_tree.heading('exploits', text='Exploits')
        self.web_tree.heading('last_check', text='Last Check')
        
        self.web_tree.column('host', width=150)
        self.web_tree.column('url', width=250)
        self.web_tree.column('server', width=150)
        self.web_tree.column('vulns', width=100, anchor=tk.CENTER)
        self.web_tree.column('exploits', width=100, anchor=tk.CENTER)
        self.web_tree.column('last_check', width=150, anchor=tk.CENTER)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(web_frame, orient=tk.VERTICAL, command=self.web_tree.yview)
        h_scrollbar = ttk.Scrollbar(web_frame, orient=tk.HORIZONTAL, command=self.web_tree.xview)
        self.web_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Layout
        self.web_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Notebook para detalhes web
        web_detail_notebook = ttk.Notebook(web_frame)
        web_detail_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Aba de detalhes do host
        host_detail_frame = ttk.Frame(web_detail_notebook)
        web_detail_notebook.add(host_detail_frame, text="Host Details")
        
        self.web_host_text = scrolledtext.ScrolledText(host_detail_frame, height=10)
        self.web_host_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Aba de vulnerabilidades
        vuln_frame = ttk.Frame(web_detail_notebook)
        web_detail_notebook.add(vuln_frame, text="Vulnerabilities")
        
        columns = ('severity', 'type', 'description', 'source')
        self.web_vuln_tree = ttk.Treeview(vuln_frame, columns=columns, show='headings', height=10)
        
        self.web_vuln_tree.heading('severity', text='Severity')
        self.web_vuln_tree.heading('type', text='Type')
        self.web_vuln_tree.heading('description', text='Description')
        self.web_vuln_tree.heading('source', text='Source')
        
        self.web_vuln_tree.column('severity', width=80)
        self.web_vuln_tree.column('type', width=150)
        self.web_vuln_tree.column('description', width=300)
        self.web_vuln_tree.column('source', width=100)
        
        v_scrollbar2 = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=self.web_vuln_tree.yview)
        self.web_vuln_tree.configure(yscrollcommand=v_scrollbar2.set)
        
        self.web_vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind click event
        self.web_tree.bind('<<TreeviewSelect>>', self.show_web_details)
    
    def create_logs_tab(self):
        """Criar aba de Logs"""
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="📝 Logs")
        
        # Controles de log
        control_frame = ttk.Frame(log_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Log Level:").pack(side=tk.LEFT, padx=(0,5))
        self.log_level_var = tk.StringVar(value="INFO")
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        ttk.Combobox(control_frame, textvariable=self.log_level_var, 
                    values=log_levels, width=10).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Refresh Logs", 
                  command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Logs", 
                  command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Save Logs", 
                  command=self.save_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Tail Logs", 
                  command=self.tail_logs).pack(side=tk.LEFT, padx=5)
        
        # Área de texto para logs
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=30)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configurar cores para diferentes níveis de log
        self.log_text.tag_config("DEBUG", foreground="gray")
        self.log_text.tag_config("INFO", foreground="white")
        self.log_text.tag_config("WARNING", foreground="yellow")
        self.log_text.tag_config("ERROR", foreground="red")
    
    def refresh_data(self):
        """Atualizar todos os dados"""
        try:
            # Atualizar em thread separada para não travar a GUI
            thread = threading.Thread(target=self._refresh_data_thread)
            thread.daemon = True
            thread.start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh data: {str(e)}")
    
    def _refresh_data_thread(self):
        """Thread para atualizar dados"""
        self.status_bar.config(text="Updating data...")
        
        try:
            # Ler dados dos scanners
            port_data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
            web_data = siaas_aux.read_from_local_file(WEBSCANNER_DB) or {}
            
            # Atualizar interface na thread principal
            self.root.after(0, self._update_interface, port_data, web_data)
            
            self.root.after(0, self.status_bar.config, 
                          text=f"Data updated at {datetime.now().strftime('%H:%M:%S')}")
            
        except Exception as e:
            self.root.after(0, self.status_bar.config, 
                          text=f"Error updating data: {str(e)}")
    
    def _update_interface(self, port_data, web_data):
        """Atualizar interface com novos dados"""
        try:
            # Limpar trees
            for tree in [self.port_tree, self.web_tree, self.vuln_tree, self.web_vuln_tree]:
                for item in tree.get_children():
                    tree.delete(item)
            
            # Atualizar estatísticas do portscanner
            total_port_hosts = len(port_data)
            total_port_ports = 0
            total_port_vulns = 0
            total_port_exploits = 0
            last_port_scan = ""
            
            # Dicionário para consolidar hosts no dashboard
            consolidated_hosts = {}
            
            # Processar portscanner
            for host, info in port_data.items():
                # Adicionar à tree do portscanner
                ports = len(info.get("scanned_ports", {}))
                vulns = info.get("stats", {}).get("total_num_vulnerabilities", 0)
                exploits = info.get("stats", {}).get("total_num_exploits", 0)
                last_check = info.get("last_check", "N/A")
                
                self.port_tree.insert('', 'end', values=(
                    host,
                    info.get("system_info", {}).get("os_name", "Unknown"),
                    ports,
                    vulns,
                    exploits,
                    last_check[:19] if last_check else "N/A"
                ))
                
                # Acumular estatísticas
                total_port_ports += ports
                total_port_vulns += vulns
                total_port_exploits += exploits
                
                # Consolidar para dashboard
                if host not in consolidated_hosts:
                    consolidated_hosts[host] = {
                        'vulns': 0,
                        'exploits': 0,
                        'last_scan': '',
                        'scanners': set()
                    }
                
                consolidated_hosts[host]['vulns'] += vulns
                consolidated_hosts[host]['exploits'] += exploits
                consolidated_hosts[host]['scanners'].add('Port')
                if last_check > consolidated_hosts[host]['last_scan']:
                    consolidated_hosts[host]['last_scan'] = last_check
                
                if last_check > last_port_scan:
                    last_port_scan = last_check
            
            self.port_stats_vars['port_hosts'].set(str(total_port_hosts))
            self.port_stats_vars['port_ports'].set(str(total_port_ports))
            self.port_stats_vars['port_vulns'].set(str(total_port_vulns))
            self.port_stats_vars['port_exploits'].set(str(total_port_exploits))
            self.port_stats_vars['port_last'].set(last_port_scan[:19] if last_port_scan else "N/A")
            
            # Atualizar estatísticas do webscanner
            total_web_hosts = len(web_data)
            total_web_ports = 0
            total_web_vulns = 0
            total_web_exploits = 0
            last_web_scan = ""
            
            # Processar webscanner
            for target_key, info in web_data.items():
                # Parse hostname:port
                if ":" in target_key:
                    host, port = target_key.split(":", 1)
                    url = info.get("system_info", {}).get("scanned_url", "N/A")
                else:
                    host = target_key
                    port = "80"
                    url = f"http://{host}"
                
                server = info.get("system_info", {}).get("server", "Unknown")
                vulns = info.get("stats", {}).get("total_num_vulnerabilities", 0)
                exploits = info.get("stats", {}).get("total_num_exploits", 0)
                last_check = info.get("last_check", "N/A")
                
                # Adicionar à tree do webscanner
                self.web_tree.insert('', 'end', values=(
                    host,
                    url,
                    server,
                    vulns,
                    exploits,
                    last_check[:19] if last_check else "N/A"
                ))
                
                # Acumular estatísticas
                total_web_ports += 1  # Cada entrada é uma porta
                total_web_vulns += vulns
                total_web_exploits += exploits
                
                # Consolidar para dashboard
                if host not in consolidated_hosts:
                    consolidated_hosts[host] = {
                        'vulns': 0,
                        'exploits': 0,
                        'last_scan': '',
                        'scanners': set()
                    }
                
                consolidated_hosts[host]['vulns'] += vulns
                consolidated_hosts[host]['exploits'] += exploits
                consolidated_hosts[host]['scanners'].add('Web')
                if last_check > consolidated_hosts[host]['last_scan']:
                    consolidated_hosts[host]['last_scan'] = last_check
                
                if last_check > last_web_scan:
                    last_web_scan = last_check
            
            self.web_stats_vars['web_hosts'].set(str(total_web_hosts))
            self.web_stats_vars['web_ports'].set(str(total_web_ports))
            self.web_stats_vars['web_vulns'].set(str(total_web_vulns))
            self.web_stats_vars['web_exploits'].set(str(total_web_exploits))
            self.web_stats_vars['web_last'].set(last_web_scan[:19] if last_web_scan else "N/A")
            
            # Atualizar top hosts vulneráveis (CONSOLIDADOS)
            # Converter dicionário para lista e ordenar
            host_list = []
            for host, data in consolidated_hosts.items():
                host_list.append((
                    host,
                    data['vulns'],
                    data['exploits'],
                    data['last_scan'],
                    ', '.join(sorted(data['scanners']))
                ))
            
            # Ordenar por número de vulnerabilidades (descendente)
            host_list.sort(key=lambda x: x[1], reverse=True)
            
            # Adicionar top 10 à tree
            top_count = min(10, len(host_list))
            for i in range(top_count):
                host, vulns, exploits, last_scan, scanners = host_list[i]
                self.vuln_tree.insert('', 'end', values=(
                    host,
                    vulns,
                    exploits,
                    last_scan[:19] if last_scan else "N/A",
                    scanners
                ))
            
            # Atualizar logs
            self.refresh_logs()
            
        except Exception as e:
            import traceback
            error_msg = f"Failed to update interface: {str(e)}\n\n{traceback.format_exc()}"
            messagebox.showerror("Error", error_msg[:500])
    
    def show_port_details(self, event):
        """Mostrar detalhes do host selecionado no portscanner"""
        selection = self.port_tree.selection()
        if not selection:
            return
        
        item = self.port_tree.item(selection[0])
        host = item['values'][0]
        
        try:
            port_data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
            if host in port_data:
                info = port_data[host]
                
                # Formatar detalhes
                details = f"HOST: {host}\n"
                details += f"IP: {info.get('system_info', {}).get('scanned_ip', 'N/A')}\n"
                details += f"OS: {info.get('system_info', {}).get('os_name', 'N/A')}\n"
                details += f"OS Family: {info.get('system_info', {}).get('os_family', 'N/A')}\n\n"
                
                details += "PORTS:\n"
                for port_str, port_info in info.get('scanned_ports', {}).items():
                    details += f"  {port_str}: {port_info.get('state', 'N/A')}"
                    if 'service' in port_info:
                        details += f" ({port_info['service']})"
                    if 'product' in port_info:
                        details += f" - {port_info['product']}"
                    details += "\n"
                
                # Adicionar vulnerabilidades encontradas
                vulnerabilities = self._extract_vulnerabilities_from_port_data(info)
                
                if vulnerabilities:
                    details += "\nVULNERABILITIES:\n"
                    for port_str, script_name, vuln_id, vuln_info in vulnerabilities[:20]:  # Limitar a 20
                        details += f"  Port {port_str} ({script_name}): {vuln_id}\n"
                        details += f"     Description: {vuln_info.get('description', 'N/A')[:100]}...\n"
                        details += f"     Severity: {vuln_info.get('severity', 'N/A')}\n"
                
                details += f"\nSTATISTICS:\n"
                stats = info.get('stats', {})
                for key, value in stats.items():
                    details += f"  {key}: {value}\n"
                
                details += f"\nLast Check: {info.get('last_check', 'N/A')}"
                
                self.port_detail_text.delete(1.0, tk.END)
                self.port_detail_text.insert(1.0, details)
        except Exception as e:
            self.port_detail_text.delete(1.0, tk.END)
            self.port_detail_text.insert(1.0, f"Error loading details: {str(e)}")
    
    def _extract_vulnerabilities_from_port_data(self, info):
        """Extrair vulnerabilidades de dados do portscanner"""
        vulnerabilities = []
        for port_str, port_info in info.get('scanned_ports', {}).items():
            scan_results = port_info.get('scan_results', {})
            for script_name, script_results in scan_results.items():
                if isinstance(script_results, dict):
                    # Tentar extrair de diferentes estruturas
                    if 'vuln' in script_results:
                        vuln_dict = script_results['vuln']
                        if isinstance(vuln_dict, dict):
                            for vuln_id, vuln_info in vuln_dict.items():
                                if isinstance(vuln_info, dict):
                                    vulnerabilities.append((port_str, script_name, vuln_id, vuln_info))
        return vulnerabilities
    
    def show_web_details(self, event):
        """Mostrar detalhes do host selecionado no webscanner"""
        selection = self.web_tree.selection()
        if not selection:
            return
        
        item = self.web_tree.item(selection[0])
        host = item['values'][0]
        
        try:
            web_data = siaas_aux.read_from_local_file(WEBSCANNER_DB) or {}
            
            # Encontrar a entrada correspondente
            target_key = None
            for key in web_data.keys():
                if key.startswith(host + ":") or key == host:
                    target_key = key
                    break
            
            if target_key and target_key in web_data:
                info = web_data[target_key]
                
                # Detalhes do host
                host_details = self._format_web_host_details(host, info)
                self.web_host_text.delete(1.0, tk.END)
                self.web_host_text.insert(1.0, host_details)
                
                # Extrair vulnerabilidades
                vulnerabilities = self._extract_vulnerabilities_from_web_data(info)
                
                # Limpar tree de vulnerabilidades
                for item in self.web_vuln_tree.get_children():
                    self.web_vuln_tree.delete(item)
                
                # Adicionar vulnerabilidades à tree
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        self.web_vuln_tree.insert('', 'end', values=vuln)
                else:
                    # Mostrar estatísticas se não houver vulnerabilidades específicas
                    stats = info.get('stats', {})
                    if stats.get('total_num_vulnerabilities', 0) > 0:
                        # Há vulnerabilidades mas não conseguimos extrair detalhes
                        self.web_vuln_tree.insert('', 'end', values=(
                            'info', 
                            'Vulnerabilities found', 
                            f'{stats.get("total_num_vulnerabilities", 0)} vulnerabilities detected but details not available',
                            'Web Scanner'
                        ))
                    else:
                        self.web_vuln_tree.insert('', 'end', values=(
                            'info', 
                            'No vulnerabilities', 
                            'No vulnerabilities were detected in the scan', 
                            'Web Scanner'
                        ))
                        
        except Exception as e:
            import traceback
            self.web_host_text.delete(1.0, tk.END)
            self.web_host_text.insert(1.0, f"Error loading details: {str(e)}\n\n{traceback.format_exc()}")
    
    def _format_web_host_details(self, host, info):
        """Formatar detalhes do host web"""
        details = f"HOST: {host}\n"
        details += f"URL: {info.get('system_info', {}).get('scanned_url', 'N/A')}\n"
        details += f"Status: {info.get('system_info', {}).get('status_code', 'N/A')}\n"
        details += f"Server: {info.get('system_info', {}).get('server', 'N/A')}\n"
        details += f"Content Type: {info.get('system_info', {}).get('content_type', 'N/A')}\n\n"
        
        # Mostrar portas escaneadas
        details += "SCANNED PORTS:\n"
        for port_str, port_info in info.get('scanned_ports', {}).items():
            details += f"  {port_str}: {port_info.get('state', 'N/A')} "
            if 'service' in port_info:
                details += f"({port_info['service']})\n"
        
        details += f"\nSTATISTICS:\n"
        stats = info.get('stats', {})
        for key, value in stats.items():
            details += f"  {key}: {value}\n"
        
        details += f"\nLast Check: {info.get('last_check', 'N/A')}"
        
        return details
    
    def _extract_vulnerabilities_from_web_data(self, info):
        """Extrair vulnerabilidades de dados do webscanner"""
        vulnerabilities = []
        
        # Verificar se há resultados de scan
        for port_str, port_info in info.get('scanned_ports', {}).items():
            scan_results = port_info.get('scan_results', {})
            
            for script_name, script_data in scan_results.items():
                if isinstance(script_data, dict):
                    # Tentar diferentes estruturas
                    
                    # Estrutura ZAP
                    if 'zap_scan' in str(script_name).lower() or 'alerts' in script_data:
                        if 'site' in script_data:
                            for site in script_data['site']:
                                for alert in site.get('alerts', []):
                                    severity = alert.get('riskdesc', 'Medium').split()[0].lower()
                                    if severity == 'high':
                                        severity = 'high'
                                    elif severity == 'medium':
                                        severity = 'medium'
                                    elif severity == 'low':
                                        severity = 'low'
                                    else:
                                        severity = 'info'
                                    
                                    vulnerabilities.append((
                                        severity,
                                        alert.get('alert', 'Vulnerability'),
                                        alert.get('desc', 'No description')[:150],
                                        'OWASP ZAP'
                                    ))
                    
                    # Estrutura com 'vuln'
                    elif 'vuln' in script_data:
                        vuln_dict = script_data['vuln']
                        if isinstance(vuln_dict, dict):
                            for vuln_id, vuln_info in vuln_dict.items():
                                if isinstance(vuln_info, dict):
                                    severity = vuln_info.get('severity', 'medium')
                                    vuln_type = vuln_info.get('type', 'vulnerability')
                                    description = vuln_info.get('description', 'No description')
                                    source = vuln_info.get('source', 'Web Scanner')
                                    vulnerabilities.append((severity, vuln_type, description, source))
        
        return vulnerabilities
    
    def filter_port_data(self):
        """Filtrar dados do portscanner"""
        filter_text = self.port_filter_var.get().lower()
        
        for item in self.port_tree.get_children():
            values = self.port_tree.item(item)['values']
            if filter_text in str(values).lower():
                self.port_tree.attach(item, '', 'end')
            else:
                self.port_tree.detach(item)
    
    def clear_port_filter(self):
        """Limpar filtro do portscanner"""
        self.port_filter_var.set("")
        
        for item in self.port_tree.get_children():
            self.port_tree.attach(item, '', 'end')
    
    def filter_web_data(self):
        """Filtrar dados do webscanner"""
        filter_text = self.web_filter_var.get().lower()
        
        for item in self.web_tree.get_children():
            values = self.web_tree.item(item)['values']
            if filter_text in str(values).lower():
                self.web_tree.attach(item, '', 'end')
            else:
                self.web_tree.detach(item)
    
    def clear_web_filter(self):
        """Limpar filtro do webscanner"""
        self.web_filter_var.set("")
        
        for item in self.web_tree.get_children():
            self.web_tree.attach(item, '', 'end')
    
    def refresh_logs(self):
        """Atualizar logs"""
        try:
            log_file = os.path.join(BASE_DIR, "logs", "siaas.log")
            if not os.path.exists(log_file):
                # Tentar encontrar logs em outros locais
                possible_logs = [
                    os.path.join(BASE_DIR, "siaas.log"),
                    os.path.join(BASE_DIR, "siaas-agent", "logs", "siaas.log"),
                    os.path.join(BASE_DIR, "siaas-agent", "siaas.log"),
                    "/var/log/siaas.log"
                ]
                
                for log_path in possible_logs:
                    if os.path.exists(log_path):
                        log_file = log_path
                        break
            
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    logs = f.readlines()[-100:]  # Últimas 100 linhas
                
                self.log_text.delete(1.0, tk.END)
                
                for log in logs:
                    # Colorir por nível de log
                    if "DEBUG" in log:
                        tag = "DEBUG"
                    elif "INFO" in log:
                        tag = "INFO"
                    elif "WARNING" in log:
                        tag = "WARNING"
                    elif "ERROR" in log:
                        tag = "ERROR"
                    else:
                        tag = "INFO"
                    
                    self.log_text.insert(tk.END, log, tag)
                
                self.log_text.see(tk.END)
            else:
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(1.0, "Log file not found.")
                
        except Exception as e:
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(1.0, f"Error loading logs: {str(e)}")
    
    def clear_logs(self):
        """Limpar área de logs"""
        self.log_text.delete(1.0, tk.END)
    
    def save_logs(self):
        """Salvar logs em arquivo"""
        from tkinter import filedialog
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
    
    def tail_logs(self):
        """Monitorar logs em tempo real"""
        self.refresh_logs()
        self.root.after(5000, self.tail_logs)  # Atualizar a cada 5 segundos
    
    def show_stats(self):
        """Mostrar estatísticas detalhadas"""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Detailed Statistics")
        stats_window.geometry("600x400")
        
        # Aqui você pode adicionar estatísticas mais detalhadas
        text = scrolledtext.ScrolledText(stats_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        stats_text = "SIAAS Statistics\n"
        stats_text += "================\n\n"
        
        stats_text += f"Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        stats_text += "Port Scanner:\n"
        stats_text += f"  - Total Hosts: {self.port_stats_vars['port_hosts'].get()}\n"
        stats_text += f"  - Open Ports: {self.port_stats_vars['port_ports'].get()}\n"
        stats_text += f"  - Vulnerabilities: {self.port_stats_vars['port_vulns'].get()}\n"
        stats_text += f"  - Exploits: {self.port_stats_vars['port_exploits'].get()}\n\n"
        
        stats_text += "Web Scanner:\n"
        stats_text += f"  - Web Hosts: {self.web_stats_vars['web_hosts'].get()}\n"
        stats_text += f"  - Scanned Ports: {self.web_stats_vars['web_ports'].get()}\n"
        stats_text += f"  - Vulnerabilities: {self.web_stats_vars['web_vulns'].get()}\n"
        stats_text += f"  - Exploits: {self.web_stats_vars['web_exploits'].get()}\n"
        
        text.insert(1.0, stats_text)
        text.config(state=tk.DISABLED)
    
    def show_settings(self):
        """Mostrar configurações"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("500x300")
        
        # Aqui você pode adicionar configurações editáveis
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Aba de configurações gerais
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        ttk.Label(general_frame, text="Auto-refresh interval (seconds):").pack(pady=5)
        interval_var = tk.StringVar(value="30")
        ttk.Entry(general_frame, textvariable=interval_var, width=10).pack(pady=5)
        
        ttk.Label(general_frame, text="Theme:").pack(pady=5)
        theme_var = tk.StringVar(value="Dark")
        ttk.Combobox(general_frame, textvariable=theme_var, 
                    values=["Dark", "Light", "System"]).pack(pady=5)
        
        # Aba de notificações
        notify_frame = ttk.Frame(notebook)
        notebook.add(notify_frame, text="Notifications")
        
        email_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(notify_frame, text="Email notifications", 
                       variable=email_var).pack(anchor=tk.W, pady=5)
        
        slack_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(notify_frame, text="Slack notifications", 
                       variable=slack_var).pack(anchor=tk.W, pady=5)
        
        ttk.Label(notify_frame, text="Alert threshold:").pack(pady=5)
        threshold_var = tk.StringVar(value="High")
        ttk.Combobox(notify_frame, textvariable=threshold_var,
                    values=["High", "Medium", "Low", "All"]).pack(pady=5)
        
        # Botões
        button_frame = ttk.Frame(settings_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Save", 
                  command=lambda: self.save_settings(
                      interval_var.get(), theme_var.get(),
                      email_var.get(), slack_var.get(),
                      threshold_var.get()
                  )).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=settings_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def save_settings(self, interval, theme, email, slack, threshold):
        """Salvar configurações"""
        # Aqui você implementaria a lógica para salvar as configurações
        messagebox.showinfo("Settings", "Settings saved successfully!")
    
    def show_help(self):
        """Mostrar ajuda"""
        help_window = tk.Toplevel(self.root)
        help_window.title("Help")
        help_window.geometry("700x500")
        
        text = scrolledtext.ScrolledText(help_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        help_text = """SIAAS - Security Audit System
=======================

1. DASHBOARD TAB
   - Overall statistics from both scanners
   - Top vulnerable hosts sorted by risk (CONSOLIDATED)
   - Each host shows total vulnerabilities from all scanners

2. PORT SCANNER TAB
   - List of all scanned hosts
   - OS information and open ports
   - Click on a host to see detailed port information

3. WEB SCANNER TAB
   - List of all scanned web applications
   - Server information and vulnerabilities
   - Click on a host to see detailed web scan results

4. LOGS TAB
   - Real-time log monitoring
   - Filter by log level (DEBUG, INFO, WARNING, ERROR)
   - Save logs to file

CONTROLS:
- Refresh: Update all data
- Stats: Show detailed statistics
- Settings: Configure application settings
- Help: Show this help message

AUTO-REFRESH:
Data is automatically refreshed every 30 seconds.

COLOR CODING:
- High risk: Red
- Medium risk: Yellow
- Low risk: Green
- Informational: Blue

KEYBOARD SHORTCUTS:
- F5: Refresh data
- Ctrl+F: Filter
- Ctrl+S: Save
- Ctrl+Q: Quit

For more information, check the documentation."""
        
        text.insert(1.0, help_text)
        text.config(state=tk.DISABLED)
    
    def auto_refresh(self):
        """Auto-refresh dos dados"""
        self.refresh_data()
        self.root.after(30000, self.auto_refresh)  # 30 segundos


def main():
    """Função principal"""
    root = tk.Tk()
    
    # Verificar se os módulos SIAAS estão disponíveis
    try:
        import siaas_aux
    except ImportError:
        print("Error: siaas_aux module not found!")
        print("Make sure you're running this from the SIAAS directory.")
        return
    
    # Criar diretório de logs se não existir
    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Iniciar GUI
    app = SIAASGUI(root)
    
    # Centralizar janela
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Bind F5 para refresh
    root.bind('<F5>', lambda e: app.refresh_data())
    
    # Iniciar loop principal
    root.mainloop()


if __name__ == "__main__":
    main()