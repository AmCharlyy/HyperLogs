"""Refined Windows onboarding UI for HyperLogs Agent."""
import sys
import threading
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

from onboarding import claim, device_info, install_windows, make_config, write_config

BG='#f5f5f7';CARD='#ffffff';TEXT='#1d1d1f';MUTED='#6e6e73';BLUE='#0071e3';GREEN='#23855b'


class Setup(tk.Tk):
    def __init__(self):
        super().__init__();self.title('HyperLogs Agent Setup');self.geometry('780x590');self.minsize(720,540)
        self.configure(bg=BG);self.info=device_info();self.result=None
        self.columnconfigure(0,weight=1);self.rowconfigure(0,weight=1)
        shell=tk.Frame(self,bg=CARD,highlightbackground='#dedee3',highlightthickness=1);shell.grid(row=0,column=0,sticky='nsew',padx=34,pady=28)
        shell.columnconfigure(0,weight=1)
        tk.Label(shell,text='◫  HYPERLOGS',font=('Segoe UI Semibold',11),fg=MUTED,bg=CARD).grid(row=0,column=0,sticky='w',padx=42,pady=(34,6))
        tk.Label(shell,text='Conecta este equipo.',font=('Segoe UI Semibold',30),fg=TEXT,bg=CARD).grid(row=1,column=0,sticky='w',padx=42)
        tk.Label(shell,text='Una configuración segura, guiada y lista para iniciar con Windows.',font=('Segoe UI',12),fg=MUTED,bg=CARD).grid(row=2,column=0,sticky='w',padx=42,pady=(5,25))
        body=tk.Frame(shell,bg='#fafafa');body.grid(row=3,column=0,sticky='nsew',padx=42);body.columnconfigure(1,weight=1)
        for row,(label,value) in enumerate((('Equipo',self.info['hostname']),('Dirección IP',self.info['ip'] or 'No detectada'),('Sistema',self.info['os_version']))):
            tk.Label(body,text=label,font=('Segoe UI Semibold',10),fg=MUTED,bg='#fafafa').grid(row=row,column=0,sticky='w',padx=18,pady=10)
            tk.Label(body,text=value,font=('Segoe UI',10),fg=TEXT,bg='#fafafa').grid(row=row,column=1,sticky='w',padx=18,pady=10)
        form=tk.Frame(shell,bg=CARD);form.grid(row=4,column=0,sticky='ew',padx=42,pady=24);form.columnconfigure(0,weight=1)
        tk.Label(form,text='Dirección de HyperLogs',font=('Segoe UI Semibold',10),fg=TEXT,bg=CARD).grid(row=0,column=0,sticky='w')
        self.server=tk.Entry(form,font=('Segoe UI',12),relief='solid',bd=1);self.server.insert(0,'https://192.168.2.20');self.server.grid(row=1,column=0,sticky='ew',ipady=10,pady=(6,15))
        tk.Label(form,text='Código temporal de vinculación',font=('Segoe UI Semibold',10),fg=TEXT,bg=CARD).grid(row=2,column=0,sticky='w')
        self.code=tk.Entry(form,font=('Consolas',15),relief='solid',bd=1);self.code.grid(row=3,column=0,sticky='ew',ipady=10,pady=(6,8))
        self.status=tk.Label(form,text='El código se genera desde HyperLogs y vence en 10 minutos.',font=('Segoe UI',9),fg=MUTED,bg=CARD);self.status.grid(row=4,column=0,sticky='w')
        self.button=tk.Button(shell,text='Vincular e instalar',font=('Segoe UI Semibold',11),fg='white',bg=BLUE,activebackground='#0062c3',activeforeground='white',bd=0,cursor='hand2',command=self.start);self.button.grid(row=5,column=0,sticky='e',padx=42,pady=(0,32),ipadx=22,ipady=11)

    def start(self):
        self.button.configure(state='disabled',text='Comprobando…');self.status.configure(text='Conectando de forma segura con HyperLogs…',fg=BLUE)
        threading.Thread(target=self.work,daemon=True).start()

    def work(self):
        try:
            sibling=Path(sys.executable).with_name('HyperLogsAgent.exe')
            if not sibling.exists():raise RuntimeError('HyperLogsAgent.exe debe estar junto al instalador.')
            certificate=Path(sys.executable).with_name('caddy-root.crt')
            if not certificate.exists():raise RuntimeError('Descarga caddy-root.crt y colócalo junto a HyperLogsSetup.exe.')
            result=claim(self.server.get(),self.code.get(),self.info,ca_cert=certificate)
            plan=install_windows(sibling,dry_run=True)
            cfg=make_config(self.server.get(),result['token'],plan['root'],ca_cert=plan['ca_cert'])
            write_config(plan['config'],cfg)
            install_windows(sibling,ca_certificate=certificate)
            self.after(0,lambda:self.success(result))
        except Exception as exc:
            self.after(0,lambda:self.failure(str(exc)))

    def success(self,result):
        self.status.configure(text='Conectado. HyperLogs Agent iniciará automáticamente con Windows.',fg=GREEN)
        self.button.configure(state='normal',text='Finalizar',command=self.destroy)
        messagebox.showinfo('Equipo vinculado',f"{result['name']} quedó registrado y protegido.")

    def failure(self,message):
        self.status.configure(text=message or 'No se pudo completar la configuración.',fg='#a22130')
        self.button.configure(state='normal',text='Intentar de nuevo')


if __name__=='__main__': Setup().mainloop()
