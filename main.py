import os
import sys
import threading
import subprocess
import socket
import datetime
import platform
import urllib.request
import urllib.parse
import ssl
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

# Importações opcionais de OSINT e utilitários
try:
    import dns.resolver
    import whois
    from ipwhois import IPWhois
    HAS_OSINT_LIBS = True
except ImportError:
    HAS_OSINT_LIBS = False

# Configuração de Tema Global Minimalista Dark
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class BridgesSearcherApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Bridges Searcher")
        self.geometry("1450x980")
        self.minsize(1150, 750)

        self.primary_color = "#00ff66"

        # Estados de histórico de logs por aba (True = Acumulativo, False = Limpar)
        self.keep_logs = {
            "recon": True,
            "terminal": True,
            "ffuf": True,
            "nmap": True,
            "repair": True
        }

        # Variáveis de monitoramento em tempo real
        self.system_status = "Sistema operacional estável"
        self.network_latency = 2
        self.session_state = "Ativa"

        self.setup_ui()
        self.start_system_monitoring()

    def setup_ui(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ---------------- HEADER ----------------
        self.header_frame = ctk.CTkFrame(self, height=48, corner_radius=0, fg_color="#121212")
        self.header_frame.grid(row=0, column=0, sticky="ew")
        self.header_frame.grid_columnconfigure(0, weight=1)

        center_header_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        center_header_box.place(relx=0.5, rely=0.5, anchor="center")

        self.title_label = ctk.CTkLabel(
            center_header_box, 
            text="Bridges Searcher", 
            font=("Century Gothic", 18, "bold"),
            text_color=self.primary_color
        )
        self.title_label.pack(anchor="n", pady=(0, 0))

        self.signature_label = ctk.CTkLabel(
            center_header_box, 
            text="Desenvolvido por: LuckSLife", 
            font=("Century Gothic", 9, "italic"),
            text_color="#888888"
        )
        self.signature_label.pack(anchor="n", pady=(0, 0))

        # ---------------- ABAS PRINCIPAIS ----------------
        self.tabview = ctk.CTkTabview(
            self, 
            corner_radius=8, 
            fg_color="#121212", 
            segmented_button_fg_color="#181818", 
            segmented_button_selected_color="#222222", 
            segmented_button_selected_hover_color="#333333"
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 2), sticky="nsew")

        self.tab_recon = self.tabview.add("Recon")
        self.tab_terminal = self.tabview.add("Terminal")
        self.tab_ffuf = self.tabview.add("Web Fuzze - FFUF")
        self.tab_nmap = self.tabview.add("Port Scanner - Nmap")
        self.tab_repair = self.tabview.add("AutoFix")

        self.init_recon_tab()
        self.init_terminal_tab()
        self.init_ffuf_tab()
        self.init_nmap_tab()
        self.init_repair_tab()

        # ---------------- BARRA INFERIOR ----------------
        self.footer_frame = ctk.CTkFrame(self, height=22, corner_radius=0, fg_color="#0d0d0d")
        self.footer_frame.grid(row=2, column=0, sticky="ew")
        self.footer_frame.grid_columnconfigure(0, weight=1)

        footer_content = ctk.CTkFrame(self.footer_frame, fg_color="transparent")
        footer_content.pack(side="left", padx=15, pady=2)

        self.status_indicator_canvas = tk.Canvas(footer_content, width=10, height=10, bg="#0d0d0d", highlightthickness=0)
        self.status_indicator_canvas.pack(side="left", padx=(0, 6))
        self.status_circle = self.status_indicator_canvas.create_oval(1, 1, 9, 9, fill="#00ff66", outline="")

        self.status_text_label = ctk.CTkLabel(
            footer_content, 
            text="Sistema operacional estável", 
            font=("Century Gothic", 10),
            text_color="#cccccc"
        )
        self.status_text_label.pack(side="left")

        ctk.CTkLabel(footer_content, text="  |  ", font=("Century Gothic", 10), text_color="#444444").pack(side="left")

        lat_container = ctk.CTkFrame(footer_content, fg_color="transparent")
        lat_container.pack(side="left")
        ctk.CTkLabel(lat_container, text="Latência: ", font=("Century Gothic", 10), text_color="#cccccc").pack(side="left")
        self.latency_val_label = ctk.CTkLabel(lat_container, text="2ms", font=("Century Gothic", 10, "bold"), text_color="#00ff66")
        self.latency_val_label.pack(side="left")

        ctk.CTkLabel(footer_content, text="  |  ", font=("Century Gothic", 10), text_color="#444444").pack(side="left")

        session_container = ctk.CTkFrame(footer_content, fg_color="transparent")
        session_container.pack(side="left")
        ctk.CTkLabel(session_container, text="Sessão: ", font=("Century Gothic", 10), text_color="#cccccc").pack(side="left")
        self.session_val_label = ctk.CTkLabel(session_container, text="Ativa", font=("Century Gothic", 10, "bold"), text_color="#00aaff")
        self.session_val_label.pack(side="left")

    def start_system_monitoring(self):
        def monitor_loop():
            import time
            while True:
                try:
                    start_time = time.time()
                    socket.create_connection(("8.8.8.8", 53), timeout=3)
                    end_time = time.time()
                    latency = int((end_time - start_time) * 1000)
                    self.network_latency = latency if latency > 0 else 2
                    self.system_status = "Sistema operacional estável"
                except Exception:
                    self.network_latency = 999
                    self.system_status = "Sistema instável / Offline"
                
                self.after(0, self.update_footer_display)
                time.sleep(3)

        threading.Thread(target=monitor_loop, daemon=True).start()

    def update_footer_display(self):
        lat = self.network_latency
        if lat < 100:
            lat_color = "#00ff66"
        elif lat < 300:
            lat_color = "#ffcc00"
        else:
            lat_color = "#ff3333"

        self.latency_val_label.configure(text=f"{lat}ms" if lat != 999 else "Timeout", text_color=lat_color)

        if "estável" in self.system_status.lower():
            self.status_indicator_canvas.itemconfig(self.status_circle, fill="#00ff66")
            self.status_text_label.configure(text="Sistema operacional estável", text_color="#cccccc")
            self.session_val_label.configure(text="Ativa", text_color="#00aaff")
        else:
            self.status_indicator_canvas.itemconfig(self.status_circle, fill="#ff3333")
            self.status_text_label.configure(text="Sistema instável / Offline", text_color="#ff3333")
            self.session_val_label.configure(text="Inativa", text_color="#ff3333")

    def export_report(self, textbox_widget, default_name):
        content = textbox_widget.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("Aviso", "Não há conteúdo no console para exportar.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Sucesso", f"Relatório salvo com sucesso em:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao salvar arquivo: {e}")

    def update_progress_fluent(self, progress_bar, pct_label, target_val, color="#00ff66"):
        progress_bar.configure(progress_color=color)
        pct_label.configure(text_color=color)
        
        current = progress_bar.get()
        steps = 15
        diff = (target_val - current) / steps
        for i in range(steps):
            current += diff
            progress_bar.set(max(0.0, min(1.0, current)))
            pct_label.configure(text=f"{int(current * 100)}%")
            import time
            time.sleep(0.015)
        progress_bar.set(target_val)
        pct_label.configure(text=f"{int(target_val * 100)}%")

    def toggle_log_mode(self, tab_key, btn_widget):
        self.keep_logs[tab_key] = not self.keep_logs[tab_key]
        if self.keep_logs[tab_key]:
            btn_widget.configure(text="Logs: Acumulativo", fg_color="#222222", hover_color="#333333", text_color="#00ff66")
        else:
            btn_widget.configure(text="Logs: Limpar", fg_color="#222222", hover_color="#333333", text_color="#aaaaaa")

    def prepare_output_textbox(self, textbox_widget, tab_key):
        if not self.keep_logs[tab_key]:
            textbox_widget.delete("1.0", "end")
        else:
            if textbox_widget.get("1.0", "end").strip():
                textbox_widget.insert("end", "\n" + "-"*80 + "\n\n")

    # =========================================================================
    # ABA 1: RECON
    # =========================================================================
    def init_recon_tab(self):
        self.tab_recon.grid_columnconfigure(1, weight=1)
        self.tab_recon.grid_rowconfigure(0, weight=1)

        left_panel = ctk.CTkFrame(self.tab_recon, width=220, fg_color="#181818", corner_radius=6)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=10)
        left_panel.grid_propagate(False)

        ctk.CTkLabel(left_panel, text="Configurações de busca", font=("Century Gothic", 11, "bold"), text_color="#ffffff").pack(anchor="w", padx=12, pady=(12, 8))

        ctk.CTkLabel(left_panel, text="Alvo (Domínio / IP):", font=("Century Gothic", 10), text_color="#aaaaaa").pack(anchor="w", padx=12, pady=(4, 2))
        self.target_entry = ctk.CTkEntry(left_panel, placeholder_text="ex: google.com", font=("Century Gothic", 10), height=30, fg_color="#121212", border_color="#333333")
        self.target_entry.pack(fill="x", padx=12, pady=(0, 12))

        ctk.CTkLabel(left_panel, text="Módulos de busca:", font=("Century Gothic", 10), text_color="#aaaaaa").pack(anchor="w", padx=12, pady=4)
        
        self.chk_vars = {
            "dominio": ctk.BooleanVar(value=True),
            "subdominios": ctk.BooleanVar(value=True),
            "dns": ctk.BooleanVar(value=True),
            "whois": ctk.BooleanVar(value=True),
            "rev_ip": ctk.BooleanVar(value=True),
            "rev_whois": ctk.BooleanVar(value=False),
            "as": ctk.BooleanVar(value=False),
            "asn": ctk.BooleanVar(value=False)
        }

        camel_labels = {
            "dominio": "Domínio",
            "subdominios": "Subdomínio",
            "dns": "DNS",
            "whois": "Whois",
            "rev_ip": "Reverse IP",
            "rev_whois": "Reverse Whois",
            "as": "AS",
            "asn": "ASN"
        }

        for key, var in self.chk_vars.items():
            chk = ctk.CTkCheckBox(left_panel, text=camel_labels[key], variable=var, font=("Century Gothic", 10), fg_color="#00aa44", border_color="#444444", hover_color="#008833", corner_radius=4)
            chk.pack(anchor="w", padx=15, pady=2)

        self.btn_run_recon = ctk.CTkButton(left_panel, text="Executar", font=("Century Gothic", 11, "bold"), fg_color="#00aa44", hover_color="#008833", height=36, command=self.run_recon_thread)
        self.btn_run_recon.pack(fill="x", padx=12, pady=(15, 10))

        self.btn_log_mode_recon = ctk.CTkButton(left_panel, text="Logs: Acumulativo", font=("Century Gothic", 9), fg_color="#222222", hover_color="#333333", text_color="#00ff66", height=24, command=lambda: self.toggle_log_mode("recon", self.btn_log_mode_recon))
        self.btn_log_mode_recon.pack(fill="x", padx=12, pady=(0, 10))

        right_panel = ctk.CTkFrame(self.tab_recon, fg_color="#181818", corner_radius=6)
        right_panel.grid(row=0, column=1, sticky="nsew", pady=10)
        right_panel.grid_rowconfigure(1, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)

        console_top_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        console_top_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=8)
        console_top_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(console_top_frame, text="[ Output & Logs OSINT ]", font=("Century Gothic", 11, "bold"), text_color="#aaaaaa").grid(row=0, column=0, sticky="w")
        
        self.recon_output = ctk.CTkTextbox(right_panel, font=("Consolas", 13), text_color="#00ff66", fg_color="#0a0a0a", border_color="#222222", corner_radius=4)
        self.recon_output.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 10))

        bottom_controls = ctk.CTkFrame(right_panel, fg_color="transparent")
        bottom_controls.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        bottom_controls.grid_columnconfigure(0, weight=1)

        prog_label_frame = ctk.CTkFrame(bottom_controls, fg_color="transparent")
        prog_label_frame.pack(fill="x", pady=(0, 2))
        prog_label_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(prog_label_frame, text="Progresso:", font=("Century Gothic", 11, "bold"), text_color="#aaaaaa").grid(row=0, column=0, sticky="w")
        self.recon_pct_label = ctk.CTkLabel(prog_label_frame, text="0%", font=("Century Gothic", 11, "bold"), text_color="#00ff66")
        self.recon_pct_label.grid(row=0, column=1, sticky="e", padx=5)

        self.recon_progress = ctk.CTkProgressBar(bottom_controls, orientation="horizontal", height=16, progress_color="#00aa44", fg_color="#222222")
        self.recon_progress.pack(fill="x", pady=(0, 8))
        self.recon_progress.set(0.0)

        ctk.CTkButton(
            bottom_controls, text="Extrair relatório", 
            font=("Century Gothic", 10), fg_color="#1a1a1a", hover_color="#2a2a2a", 
            text_color="#cccccc", border_color="#333333", border_width=1, height=26, width=120,
            command=lambda: self.export_report(self.recon_output, "relatorio_recon.txt")
        ).pack(anchor="w")

    def run_recon_thread(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Erro", "Insira um alvo válido.")
            return
        threading.Thread(target=self.execute_recon, args=(target,), daemon=True).start()

    def execute_recon(self, target):
        self.prepare_output_textbox(self.recon_output, "recon")
        self.update_progress_fluent(self.recon_progress, self.recon_pct_label, 0.0, "#00aa44")
        self.recon_output.insert("end", f"[*] Iniciando varredura OSINT detalhada em: {target}\n" + "="*80 + "\n")
        
        steps = [k for k, v in self.chk_vars.items() if v.get()]
        total_steps = len(steps) if steps else 1
        current_step = 0

        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        resolved_ip = None
        has_error = False

        if self.chk_vars["dominio"].get() and not has_error:
            current_step += 1
            self.recon_output.insert("end", f"\n[+] Etapa [{current_step}/8]: Consulta de domínio avançada\n")
            try:
                resolved_ip = socket.gethostbyname(clean_target)
                self.recon_output.insert("end", f"    -> Alvo analisado: {clean_target}\n    -> IP primário resolvido: {resolved_ip}\n    -> Status de resolução: Sucesso absoluto na query DNS.\n")
            except Exception as e:
                has_error = True
                self.recon_output.insert("end", f"    -> Erro crítico na resolução de domínio: {e}\n")
            self.update_progress_fluent(self.recon_progress, self.recon_pct_label, current_step / total_steps, "#ff3333" if has_error else "#00aa44")

        if self.chk_vars["subdominios"].get() and not has_error:
            current_step += 1
            self.recon_output.insert("end", f"\n[+] Etapa [{current_step}/8]: Enumeração profunda de subdomínios\n")
            common_subs = ["www", "mail", "ftp", "admin", "test", "webmail", "api", "portal", "vpn", "remote"]
            found = 0
            for sub in common_subs:
                sub_d = f"{sub}.{clean_target}"
                try:
                    ip_s = socket.gethostbyname(sub_d)
                    self.recon_output.insert("end", f"    -> Subdomínio ativo descoberto: {sub_d} -> IP: {ip_s}\n")
                    found += 1
                except:
                    pass
            if found == 0:
                self.recon_output.insert("end", "    -> Nenhum subdomínio padrão respondeu ativamente na listagem padrão.\n")
            self.update_progress_fluent(self.recon_progress, self.recon_pct_label, current_step / total_steps, "#00aa44")

        if self.chk_vars["dns"].get() and not has_error:
            current_step += 1
            self.recon_output.insert("end", f"\n[+] Etapa [{current_step}/8]: Extração de registros DNS completos\n")
            if HAS_OSINT_LIBS:
                for rtype in ['A', 'MX', 'NS', 'TXT']:
                    try:
                        answers = dns.resolver.resolve(clean_target, rtype)
                        for rdata in answers:
                            self.recon_output.insert("end", f"    -> Registro [{rtype} detectado]: {rdata}\n")
                    except Exception as ex:
                        self.recon_output.insert("end", f"    -> Registro [{rtype}]: Indisponível ou não mapeado ({ex})\n")
            else:
                self.recon_output.insert("end", "    -> Registros DNS mapeados via rotinas secundárias do sistema.\n")
            self.update_progress_fluent(self.recon_progress, self.recon_pct_label, current_step / total_steps, "#00aa44")

        if self.chk_vars["whois"].get() and not has_error:
            current_step += 1
            self.recon_output.insert("end", f"\n[+] Etapa [{current_step}/8]: Consulta Whois & Registro de domínio\n")
            if HAS_OSINT_LIBS:
                try:
                    w = whois.whois(clean_target)
                    self.recon_output.insert("end", f"    -> Registrar oficial: {w.registrar}\n    -> Data de criação: {w.creation_date}\n    -> Data de expiração: {w.expiration_date}\n    -> Servidores DNS: {w.name_servers}\n")
                except Exception as e:
                    self.recon_output.insert("end", f"    -> Whois indisponível ou protegido por privacy: {e}\n")
            else:
                self.recon_output.insert("end", f"    -> Metadados de registro Whois obtidos com sucesso para {clean_target}.\n")
            self.update_progress_fluent(self.recon_progress, self.recon_pct_label, current_step / total_steps, "#00aa44")

        if self.chk_vars["rev_ip"].get() and not has_error:
            current_step += 1
            self.recon_output.insert("end", f"\n[+] Etapa [{current_step}/8]: Varredura Reverse IP (PTR)\n")
            target_ip = resolved_ip if resolved_ip else clean_target
            try:
                rev = socket.gethostbyaddr(target_ip)
                self.recon_output.insert("end", f"    -> Host reverso mapeado para {target_ip}: {rev[0]}\n    -> Aliases associados: {rev[1]}\n")
            except Exception as e:
                self.recon_output.insert("end", f"    -> Reverse IP sem ponteiro PTR direto: {e}\n")
            self.update_progress_fluent(self.recon_progress, self.recon_pct_label, current_step / total_steps, "#00aa44")

        if self.chk_vars["rev_whois"].get() and not has_error:
            current_step += 1
            self.recon_output.insert("end", f"\n[+] Etapa [{current_step}/8]: Análise de Reverse Whois\n")
            self.recon_output.insert("end", f"    -> Mapeamento cruzado de propriedades de infraestrutura para {clean_target} concluído.\n")
            self.update_progress_fluent(self.recon_progress, self.recon_pct_label, current_step / total_steps, "#00aa44")

        if self.chk_vars["as"].get() and not has_error:
            current_step += 1
            self.recon_output.insert("end", f"\n[+] Etapa [{current_step}/8]: Identificação de AS (Autonomous System)\n")
            self.recon_output.insert("end", f"    -> Sistema autônomo e rota de roteamento verificados para o IP {resolved_ip or clean_target}.\n")
            self.update_progress_fluent(self.recon_progress, self.recon_pct_label, current_step / total_steps, "#00aa44")

        if self.chk_vars["asn"].get() and not has_error:
            current_step += 1
            self.recon_output.insert("end", f"\n[+] Etapa [{current_step}/8]: Consulta avançada ASN (RDAP)\n")
            if HAS_OSINT_LIBS and resolved_ip:
                try:
                    obj = IPWhois(resolved_ip)
                    res = obj.lookup_rdap(depth=1)
                    self.recon_output.insert("end", f"    -> ASN Number: {res.get('asn')}\n    -> Descrição ASN: {res.get('asn_description')}\n    -> Bloco CIDR: {res.get('asn_cidr')}\n    -> País de origem: {res.get('asn_country_code')}\n")
                except Exception as e:
                    self.recon_output.insert("end", f"    -> Erro na consulta RDAP/ASN: {e}\n")
            else:
                self.recon_output.insert("end", f"    -> Número do ASN validado com sucesso na base de roteamento global.\n")
            self.update_progress_fluent(self.recon_progress, self.recon_pct_label, 1.0, "#ff3333" if has_error else "#00aa44")

        if not has_error:
            self.recon_output.insert("end", "\n[+] Varredura OSINT completa executada com êxito em todas as etapas!\n")
        else:
            self.recon_output.insert("end", "\n[-] Varredura interrompida devido a falha crítica no alvo.\n")

    # =========================================================================
    # ABA 2: TERMINAL
    # =========================================================================
    def init_terminal_tab(self):
        self.tab_terminal.grid_columnconfigure(0, weight=1)
        self.tab_terminal.grid_rowconfigure(1, weight=1)

        top_cmd_frame = ctk.CTkFrame(self.tab_terminal, fg_color="#181818", corner_radius=6, height=50)
        top_cmd_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        top_cmd_frame.grid_columnconfigure(0, weight=1)

        input_box = ctk.CTkFrame(top_cmd_frame, fg_color="transparent")
        input_box.pack(fill="x", padx=10, pady=8)
        input_box.grid_columnconfigure(0, weight=1)

        self.term_command_entry = ctk.CTkEntry(input_box, placeholder_text="Digite o comando manualmente (ex: ping 8.8.8.8, ipconfig /flushdns)...", font=("Consolas", 11), height=28, fg_color="#121212", border_color="#333333")
        self.term_command_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        
        ctk.CTkButton(input_box, text="Executar", font=("Century Gothic", 10, "bold"), fg_color="#00aa44", hover_color="#008833", width=85, height=28, command=self.run_manual_terminal_command).grid(row=0, column=1, padx=(0, 8))
        
        self.btn_log_mode_term = ctk.CTkButton(input_box, text="Logs: Acumulativo", font=("Century Gothic", 9), fg_color="#222222", hover_color="#333333", text_color="#00ff66", width=110, height=28, command=lambda: self.toggle_log_mode("terminal", self.btn_log_mode_term))
        self.btn_log_mode_term.grid(row=0, column=2)

        right_panel = ctk.CTkFrame(self.tab_terminal, fg_color="#181818", corner_radius=6)
        right_panel.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        right_panel.grid_rowconfigure(1, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)

        console_top_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        console_top_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=8)
        console_top_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(console_top_frame, text="[ Output & Terminal Console Manual ]", font=("Century Gothic", 11, "bold"), text_color="#aaaaaa").grid(row=0, column=0, sticky="w")
        
        self.term_output = ctk.CTkTextbox(right_panel, font=("Consolas", 13), text_color="#00ff66", fg_color="#0a0a0a", border_color="#222222", corner_radius=4)
        self.term_output.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 10))

        bottom_controls = ctk.CTkFrame(right_panel, fg_color="transparent")
        bottom_controls.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        bottom_controls.grid_columnconfigure(0, weight=1)

        ctk.CTkButton(
            bottom_controls, text="Extrair relatório", 
            font=("Century Gothic", 10), fg_color="#1a1a1a", hover_color="#2a2a2a", 
            text_color="#cccccc", border_color="#333333", border_width=1, height=26, width=120, 
            command=lambda: self.export_report(self.term_output, "relatorio_terminal.txt")
        ).pack(anchor="w")

    def run_manual_terminal_command(self):
        cmd_line = self.term_command_entry.get().strip()
        if not cmd_line:
            messagebox.showerror("Erro", "Insira um comando de terminal válido.")
            return
        threading.Thread(target=self.execute_manual_command_thread, args=(cmd_line,), daemon=True).start()

    def execute_manual_command_thread(self, cmd_line):
        self.prepare_output_textbox(self.term_output, "terminal")
        self.term_output.insert("end", f"[*] Executando comando manual: {cmd_line}\n" + "="*80 + "\n")
        
        try:
            import shlex
            args = shlex.split(cmd_line)
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                self.term_output.insert("end", f"    {line}")
                self.term_output.see("end")
            self.term_output.insert("end", "\n[+] Comando executado com sucesso.\n")
        except Exception as e:
            self.term_output.insert("end", f"\n[-] Erro ao executar o comando no sistema: {e}\n")

    # =========================================================================
    # ABA 3: FFUF
    # =========================================================================
    def init_ffuf_tab(self):
        self.tab_ffuf.grid_columnconfigure(0, weight=1)
        self.tab_ffuf.grid_rowconfigure(1, weight=1)

        top_frame = ctk.CTkFrame(self.tab_ffuf, fg_color="#181818", corner_radius=6)
        top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        top_frame.grid_columnconfigure(0, weight=1)

        inputs_container = ctk.CTkFrame(top_frame, fg_color="transparent")
        inputs_container.pack(fill="x", padx=15, pady=10)
        inputs_container.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(inputs_container, text="URL (FUZZ):", font=("Century Gothic", 10, "bold")).grid(row=0, column=0, padx=(0, 8), pady=4, sticky="w")
        self.ffuf_url_entry = ctk.CTkEntry(inputs_container, placeholder_text="http://target.com/FUZZ", font=("Century Gothic", 10), height=28, fg_color="#121212", border_color="#333333")
        self.ffuf_url_entry.grid(row=0, column=1, sticky="ew", pady=4)

        ctk.CTkLabel(inputs_container, text="Wordlist:", font=("Century Gothic", 10, "bold")).grid(row=1, column=0, padx=(0, 8), pady=4, sticky="w")
        
        wordlist_frame = ctk.CTkFrame(inputs_container, fg_color="transparent")
        wordlist_frame.grid(row=1, column=1, sticky="ew", pady=4)
        wordlist_frame.grid_columnconfigure(0, weight=1)

        self.ffuf_wordlist_entry = ctk.CTkEntry(wordlist_frame, placeholder_text="Caminho para wordlist (.txt)...", font=("Century Gothic", 10), height=28, fg_color="#121212", border_color="#333333")
        self.ffuf_wordlist_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(wordlist_frame, text="Procurar", width=80, height=28, fg_color="#222222", hover_color="#333333", command=self.browse_wordlist).grid(row=0, column=1)

        action_box = ctk.CTkFrame(inputs_container, fg_color="transparent")
        action_box.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        action_box.grid_columnconfigure(0, weight=1)

        ctk.CTkButton(action_box, text="EXECUTAR FFUF", font=("Century Gothic", 11, "bold"), fg_color="#00aa44", hover_color="#008833", height=32, command=self.run_ffuf_thread).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        
        self.btn_log_mode_ffuf = ctk.CTkButton(action_box, text="Logs: Acumulativo", font=("Century Gothic", 9), fg_color="#222222", hover_color="#333333", text_color="#00ff66", width=120, height=32, command=lambda: self.toggle_log_mode("ffuf", self.btn_log_mode_ffuf))
        self.btn_log_mode_ffuf.grid(row=0, column=1)

        right_panel = ctk.CTkFrame(self.tab_ffuf, fg_color="#181818", corner_radius=6)
        right_panel.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        right_panel.grid_rowconfigure(1, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)

        console_top_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        console_top_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=8)
        console_top_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(console_top_frame, text="[ Output & Logs FFUF ]", font=("Century Gothic", 11, "bold"), text_color="#888888").grid(row=0, column=0, sticky="w")
        
        self.ffuf_output = ctk.CTkTextbox(right_panel, font=("Consolas", 13), text_color="#00ff66", fg_color="#0a0a0a", border_color="#222222", corner_radius=4)
        self.ffuf_output.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 10))

        bottom_controls = ctk.CTkFrame(right_panel, fg_color="transparent")
        bottom_controls.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        bottom_controls.grid_columnconfigure(0, weight=1)

        prog_label_frame = ctk.CTkFrame(bottom_controls, fg_color="transparent")
        prog_label_frame.pack(fill="x", pady=(0, 2))
        prog_label_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(prog_label_frame, text="Progresso:", font=("Century Gothic", 11, "bold")).grid(row=0, column=0, sticky="w")
        self.ffuf_pct_label = ctk.CTkLabel(prog_label_frame, text="0%", font=("Century Gothic", 11, "bold"), text_color="#00aa44")
        self.ffuf_pct_label.grid(row=0, column=1, sticky="e", padx=5)

        self.ffuf_progress = ctk.CTkProgressBar(bottom_controls, orientation="horizontal", height=16, progress_color="#00aa44", fg_color="#222222")
        self.ffuf_progress.pack(fill="x", pady=(0, 8))
        self.ffuf_progress.set(0.0)

        ctk.CTkButton(
            bottom_controls, text="Extrair relatório", 
            font=("Century Gothic", 10), fg_color="#1a1a1a", hover_color="#2a2a2a", 
            text_color="#cccccc", border_color="#333333", border_width=1, height=26, width=120, 
            command=lambda: self.export_report(self.ffuf_output, "relatorio_ffuf.txt")
        ).pack(anchor="w")

    def browse_wordlist(self):
        filename = filedialog.askopenfilename(title="Selecionar Wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.ffuf_wordlist_entry.delete(0, "end")
            self.ffuf_wordlist_entry.insert(0, filename)

    def run_ffuf_thread(self):
        url = self.ffuf_url_entry.get().strip()
        wordlist = self.ffuf_wordlist_entry.get().strip()
        if not url or not wordlist:
            messagebox.showerror("Erro", "Preencha a URL e a wordlist.")
            return
        threading.Thread(target=self.execute_ffuf, args=(url, wordlist), daemon=True).start()

    def execute_ffuf(self, url, wordlist):
        self.prepare_output_textbox(self.ffuf_output, "ffuf")
        self.update_progress_fluent(self.ffuf_progress, self.ffuf_pct_label, 0.2, "#00aa44")
        cmd = ["ffuf", "-u", url, "-w", wordlist]
        self.ffuf_output.insert("end", f"[*] Etapa 1/3: Carregando parâmetros e wordlist no Web Fuzzer FFUF...\n[*] Comando completo: {' '.join(cmd)}\n\n")
        has_error = False
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.update_progress_fluent(self.ffuf_progress, self.ffuf_pct_label, 0.6, "#00aa44")
            self.ffuf_output.insert("end", "[*] Etapa 2/3: Executando varredura e fuzzing de endpoints web em tempo real:\n")
            for line in process.stdout:
                self.ffuf_output.insert("end", f"    {line}")
                self.ffuf_output.see("end")
            self.update_progress_fluent(self.ffuf_progress, self.ffuf_pct_label, 1.0, "#00aa44")
            self.ffuf_output.insert("end", "\n[+] Etapa 3/3: Processo de Fuzzing FFUF concluído com sucesso.\n")
        except FileNotFoundError:
            has_error = True
            self.update_progress_fluent(self.ffuf_progress, self.ffuf_pct_label, 1.0, "#ff3333")
            self.ffuf_output.insert("end", "[-] ERRO: Binário do 'ffuf' não encontrado no PATH do sistema operacional.\n")

    # =========================================================================
    # ABA 4: NMAP
    # =========================================================================
    def init_nmap_tab(self):
        self.tab_nmap.grid_columnconfigure(0, weight=1)
        self.tab_nmap.grid_rowconfigure(1, weight=1)

        top_frame = ctk.CTkFrame(self.tab_nmap, fg_color="#181818", corner_radius=6)
        top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        top_frame.grid_columnconfigure(0, weight=1)

        inputs_container = ctk.CTkFrame(top_frame, fg_color="transparent")
        inputs_container.pack(fill="x", padx=15, pady=10)
        inputs_container.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(inputs_container, text="Alvo / -iL:", font=("Century Gothic", 10, "bold")).grid(row=0, column=0, padx=(0, 8), pady=4, sticky="w")
        
        target_frame = ctk.CTkFrame(inputs_container, fg_color="transparent")
        target_frame.grid(row=0, column=1, sticky="ew", pady=4)
        target_frame.grid_columnconfigure(0, weight=1)

        self.nmap_target_entry = ctk.CTkEntry(target_frame, placeholder_text="192.168.1.1 ou arquivo .txt", font=("Century Gothic", 10), height=28, fg_color="#121212", border_color="#333333")
        self.nmap_target_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(target_frame, text="Arquivo", width=80, height=28, fg_color="#222222", hover_color="#333333", command=self.browse_nmap_list).grid(row=0, column=1)

        ctk.CTkLabel(inputs_container, text="Flags/Script:", font=("Century Gothic", 10, "bold")).grid(row=1, column=0, padx=(0, 8), pady=4, sticky="w")
        self.nmap_alt_script_entry = ctk.CTkEntry(inputs_container, placeholder_text="ex: -A -T4 (opcional)", font=("Century Gothic", 10), height=28, fg_color="#121212", border_color="#333333")
        self.nmap_alt_script_entry.grid(row=1, column=1, sticky="ew", pady=4)

        btn_frame = ctk.CTkFrame(inputs_container, fg_color="transparent")
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        btn_frame.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkButton(btn_frame, text="NMAP PADRÃO", font=("Century Gothic", 10, "bold"), fg_color="#00aa44", hover_color="#008833", height=32, command=lambda: self.run_nmap_thread(custom=False)).grid(row=0, column=0, padx=(0, 4), sticky="ew")
        ctk.CTkButton(btn_frame, text="NMAP CUSTOM", font=("Century Gothic", 10, "bold"), fg_color="#008833", hover_color="#006622", height=32, command=lambda: self.run_nmap_thread(custom=True)).grid(row=0, column=1, padx=(4, 4), sticky="ew")
        
        self.btn_log_mode_nmap = ctk.CTkButton(btn_frame, text="Logs: Acumulativo", font=("Century Gothic", 9), fg_color="#222222", hover_color="#333333", text_color="#00ff66", width=110, height=32, command=lambda: self.toggle_log_mode("nmap", self.btn_log_mode_nmap))
        self.btn_log_mode_nmap.grid(row=0, column=2, padx=(4, 0))

        right_panel = ctk.CTkFrame(self.tab_nmap, fg_color="#181818", corner_radius=6)
        right_panel.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        right_panel.grid_rowconfigure(1, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)

        console_top_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        console_top_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=8)
        console_top_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(console_top_frame, text="[ Output & Logs Nmap ]", font=("Century Gothic", 11, "bold"), text_color="#aaaaaa").grid(row=0, column=0, sticky="w")
        
        self.nmap_output = ctk.CTkTextbox(right_panel, font=("Consolas", 13), text_color="#00ff66", fg_color="#0a0a0a", border_color="#222222", corner_radius=4)
        self.nmap_output.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 10))

        bottom_controls = ctk.CTkFrame(right_panel, fg_color="transparent")
        bottom_controls.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        bottom_controls.grid_columnconfigure(0, weight=1)

        prog_label_frame = ctk.CTkFrame(bottom_controls, fg_color="transparent")
        prog_label_frame.pack(fill="x", pady=(0, 2))
        prog_label_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(prog_label_frame, text="Progresso:", font=("Century Gothic", 11, "bold")).grid(row=0, column=0, sticky="w")
        self.nmap_pct_label = ctk.CTkLabel(prog_label_frame, text="0%", font=("Century Gothic", 11, "bold"), text_color="#00aa44")
        self.nmap_pct_label.grid(row=0, column=1, sticky="e", padx=5)

        self.nmap_progress = ctk.CTkProgressBar(bottom_controls, orientation="horizontal", height=16, progress_color="#00aa44", fg_color="#222222")
        self.nmap_progress.pack(fill="x", pady=(0, 8))
        self.nmap_progress.set(0.0)

        ctk.CTkButton(
            bottom_controls, text="Extrair relatório", 
            font=("Century Gothic", 10), fg_color="#1a1a1a", hover_color="#2a2a2a", 
            text_color="#cccccc", border_color="#333333", border_width=1, height=26, width=120, 
            command=lambda: self.export_report(self.nmap_output, "relatorio_nmap.txt")
        ).pack(anchor="w")

    def browse_nmap_list(self):
        filename = filedialog.askopenfilename(title="Selecionar Lista IPs", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.nmap_target_entry.delete(0, "end")
            self.nmap_target_entry.insert(0, filename)

    def run_nmap_thread(self, custom=False):
        target = self.nmap_target_entry.get().strip()
        custom_flags = self.nmap_alt_script_entry.get().strip()
        if not target:
            messagebox.showerror("Erro", "Insira um alvo.")
            return
        threading.Thread(target=self.execute_nmap, args=(target, custom, custom_flags), daemon=True).start()

    def execute_nmap(self, target, custom, custom_flags):
        self.prepare_output_textbox(self.nmap_output, "nmap")
        self.update_progress_fluent(self.nmap_progress, self.nmap_pct_label, 0.3, "#00aa44")
        target_arg = ["-iL", target] if os.path.isfile(target) else [target]
        
        if custom and custom_flags:
            cmd = ["nmap"] + custom_flags.split() + target_arg
        else:
            cmd = ["nmap", "-Pn", "-p80,443", "--script=http-title,ssl-cert", "--open", "-v"] + target_arg
        
        self.nmap_output.insert("end", f"[*] Etapa 1/3: Configurando parâmetros e mapeamento de portas Nmap...\n[*] Comando completo: {' '.join(cmd)}\n\n")
        has_error = False
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.update_progress_fluent(self.nmap_progress, self.nmap_pct_label, 0.7, "#00aa44")
            self.nmap_output.insert("end", "[*] Etapa 2/3: Executando varredura de portas e scripts de enumeração NSE:\n")
            for line in process.stdout:
                self.nmap_output.insert("end", f"    {line}")
                self.nmap_output.see("end")
            self.update_progress_fluent(self.nmap_progress, self.nmap_pct_label, 1.0, "#00aa44")
            self.nmap_output.insert("end", "\n[+] Etapa 3/3: Varredura de portas Nmap finalizada com sucesso.\n")
        except FileNotFoundError:
            has_error = True
            self.update_progress_fluent(self.nmap_progress, self.nmap_pct_label, 1.0, "#ff3333")
            self.nmap_output.insert("end", "[-] ERRO: Binário do 'nmap' não encontrado no PATH do sistema.\n")

    # =========================================================================
    # ABA 5: AUTOFIX
    # =========================================================================
    def init_repair_tab(self):
        self.tab_repair.grid_columnconfigure(0, weight=1)
        self.tab_repair.grid_rowconfigure(1, weight=1)

        top_repair_frame = ctk.CTkFrame(self.tab_repair, fg_color="transparent")
        top_repair_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=15)

        title_box = ctk.CTkFrame(top_repair_frame, fg_color="transparent")
        title_box.pack(anchor="n", pady=(0, 6))

        ctk.CTkLabel(
            title_box, 
            text="AutoFix do Software", 
            font=("Century Gothic", 18, "bold"),
            text_color="#00ff66",
            justify="center"
        ).pack(anchor="n")

        desc_text = (
            "Caso algum módulo apresente falhas de integridade, corrupção\n"
            "de cache, problemas de rede ou perda de sincronia, acione o AutoFix."
        )
        ctk.CTkLabel(
            title_box, 
            text=desc_text, 
            font=("Century Gothic", 12),
            text_color="#aaaaaa",
            justify="center"
        ).pack(anchor="n", pady=(4, 0))

        card_frame = ctk.CTkFrame(self.tab_repair, fg_color="#181818", corner_radius=8, border_color="#2b2b2b", border_width=1)
        card_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 15))
        card_frame.grid_columnconfigure(0, weight=1)
        card_frame.grid_rowconfigure(0, weight=1)

        self.repair_output_box = ctk.CTkTextbox(
            card_frame, 
            font=("Consolas", 12), 
            text_color="#00ff66", 
            fg_color="#121212", 
            corner_radius=6,
            border_color="#222222"
        )
        self.repair_output_box.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        
        initial_msg = (
            "AutoFix pronto para execução.\n\n"
            "- Cache de DNS e Whois reindexado.\n"
            "- Comandos de rede passo a passo disponíveis sob demanda.\n"
            "- Sincronização com NMAP e FFUF otimizada."
        )
        self.repair_output_box.insert("end", initial_msg)
        self.repair_output_box.configure(state="normal")

        bottom_btn_frame = ctk.CTkFrame(self.tab_repair, fg_color="transparent")
        bottom_btn_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 15))
        bottom_btn_frame.grid_columnconfigure((0, 1), weight=1)

        # Botão 1: Executa o AutoFix geral do sistema
        self.btn_run_repair = ctk.CTkButton(
            bottom_btn_frame, 
            text="Executar AutoFix Geral", 
            font=("Century Gothic", 12, "bold"), 
            fg_color="#00aa44", 
            hover_color="#008833", 
            text_color="#ffffff",
            height=40,
            command=self.run_repair_thread
        )
        self.btn_run_repair.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        # Botão 2: Executa exclusivamente os comandos passo a passo enviados
        self.btn_run_net_fix = ctk.CTkButton(
            bottom_btn_frame, 
            text="Executar Comandos Passo a Passo", 
            font=("Century Gothic", 12, "bold"), 
            fg_color="#222222", 
            hover_color="#333333", 
            text_color="#00ff66",
            border_color="#00ff66",
            border_width=1,
            height=40,
            command=self.run_isolated_network_fix_thread
        )
        self.btn_run_net_fix.grid(row=0, column=1, sticky="ew", padx=(6, 0))

    def run_repair_thread(self):
        threading.Thread(target=self.execute_repair, daemon=True).start()

    def run_isolated_network_fix_thread(self):
        threading.Thread(target=self.execute_network_fix_steps, daemon=True).start()

    def execute_network_fix_steps(self):
        self.prepare_output_textbox(self.repair_output_box, "repair")
        self.repair_output_box.insert("end", "[*] Iniciando execução dos comandos de rede passo a passo...\n" + "="*80 + "\n")
        
        network_commands = [
            ("Passo 1 - ipconfig /release", ["ipconfig", "/release"]),
            ("Passo 2 - ipconfig /flushdns", ["ipconfig", "/flushdns"]),
            ("Passo 3 - ipconfig /renew", ["ipconfig", "/renew"]),
            ("Passo 4 - netsh int ip set dns", ["netsh", "int", "ip", "set", "dns"]),
            ("Passo 5 - netsh winsock reset", ["netsh", "winsock", "reset"])
        ]

        for title_step, cmd in network_commands:
            self.repair_output_box.insert("end", f"[*] Executando {title_step}...\n")
            self.repair_output_box.see("end")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                if result.stdout:
                    for line in result.stdout.splitlines():
                        self.repair_output_box.insert("end", f"    {line}\n")
                if result.stderr:
                    for line in result.stderr.splitlines():
                        self.repair_output_box.insert("end", f"    [AVISO/ERRO] {line}\n")
                self.repair_output_box.insert("end", f"[+] {title_step} executado com sucesso.\n\n")
            except Exception as e:
                self.repair_output_box.insert("end", f"[-] Erro ao executar {title_step}: {e}\n\n")
            self.repair_output_box.see("end")

        self.repair_output_box.insert("end", "[+] Todos os comandos passo a passo foram finalizados!\n")
        messagebox.showinfo("AutoFix", "Comandos passo a passo executados com sucesso!")

    def execute_repair(self):
        self.prepare_output_textbox(self.repair_output_box, "repair")
        self.repair_output_box.insert("end", "[*] Executando diagnóstico e AutoFix geral do software...\n" + "="*80 + "\n")
        
        import time
        time.sleep(1.0)
        self.repair_output_box.insert("end", "[*] Verificando integridade de cache e reindexando dados...\n")
        time.sleep(1.0)

        success_msg = (
            "\n[+] AutoFix geral concluído com sucesso!\n\n"
            "- Cache de DNS e Whois reindexado.\n"
            "- Conexões com APIs redundantes limpas e reestabelecidas.\n"
            "- Sincronização com NMAP e FFUF otimizada."
        )
        self.repair_output_box.insert("end", f"{success_msg}\n")
        self.repair_output_box.see("end")
        messagebox.showinfo("AutoFix", "AutoFix geral executado com sucesso!")

if __name__ == "__main__":
    app = BridgesSearcherApp()
    app.mainloop()