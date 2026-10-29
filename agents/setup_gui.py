"""Single-file Windows installer, diagnostics, and repair UI for HyperLogs Agent."""
import json
import os
from pathlib import Path
import sys
import threading
import tkinter as tk
from tkinter import messagebox

from onboarding import (claim, device_info, enable_windows_auditing, friendly_error,
                        install_windows, make_config, repair_config, run_agent_once,
                        server_health, start_windows_task, write_config)

BG='#f5f5f7';CARD='#ffffff';TEXT='#1d1d1f';MUTED='#6e6e73';BLUE='#0071e3';GREEN='#23855b';RED='#a22130';LINE='#dedee3'
STEPS=('Paquete integrado','Conectividad y TLS','Identidad del equipo','Permisos y archivos',
       'Auditoría de Windows','Envío de prueba','Inicio automático')


def resource(name):
    bundled=Path(getattr(sys,'_MEIPASS',Path(sys.executable).parent))/name
    return bundled if bundled.exists() else Path(sys.executable).with_name(name)


def deployment_server():
    try:return json.loads(resource('deployment.json').read_text(encoding='utf-8'))['server']
    except (OSError,KeyError,ValueError,TypeError):return 'https://localhost:8443'


class Setup(tk.Tk):
    def __init__(self):
        super().__init__();self.title('HyperLogs Setup');self.geometry('860x700');self.minsize(790,650)
        self.configure(bg=BG);self.info=device_info();self.rows={};self.busy=False
        self.root_dir=Path(os.environ.get('ProgramData',r'C:\ProgramData'))/'HyperLogs';self.existing=(self.root_dir/'agent.json').is_file()
        self.columnconfigure(0,weight=1);self.rowconfigure(0,weight=1)
        shell=tk.Frame(self,bg=CARD,highlightbackground=LINE,highlightthickness=1);shell.grid(row=0,column=0,sticky='nsew',padx=34,pady=26)
        shell.columnconfigure(0,weight=3);shell.columnconfigure(1,weight=2);shell.rowconfigure(3,weight=1)
        tk.Label(shell,text='HYPERLOGS  /  WINDOWS',font=('Segoe UI Semibold',10),fg=MUTED,bg=CARD).grid(row=0,column=0,columnspan=2,sticky='w',padx=40,pady=(30,6))
        tk.Label(shell,text='Tu equipo, listo.',font=('Segoe UI Semibold',30),fg=TEXT,bg=CARD).grid(row=1,column=0,columnspan=2,sticky='w',padx=40)
        tk.Label(shell,text='Instala, comprueba y repara cada pieza antes de comenzar a monitorear.',font=('Segoe UI',11),fg=MUTED,bg=CARD).grid(row=2,column=0,columnspan=2,sticky='w',padx=40,pady=(5,22))
        form=tk.Frame(shell,bg=CARD);form.grid(row=3,column=0,sticky='nsew',padx=(40,22));form.columnconfigure(0,weight=1)
        info=tk.Frame(form,bg='#f7f7f9');info.grid(row=0,column=0,sticky='ew',pady=(0,18));info.columnconfigure(1,weight=1)
        for row,(label,value) in enumerate((('Equipo',self.info['hostname']),('Dirección IP',self.info['ip'] or 'No detectada'),('Sistema',self.info['os_version']))):
            tk.Label(info,text=label,font=('Segoe UI Semibold',9),fg=MUTED,bg='#f7f7f9').grid(row=row,column=0,sticky='w',padx=16,pady=8)
            tk.Label(info,text=value,font=('Segoe UI',9),fg=TEXT,bg='#f7f7f9').grid(row=row,column=1,sticky='w',padx=16,pady=8)
        tk.Label(form,text='Servidor HyperLogs',font=('Segoe UI Semibold',10),fg=TEXT,bg=CARD).grid(row=1,column=0,sticky='w')
        self.server=tk.Entry(form,font=('Segoe UI',11),relief='solid',bd=1);self.server.insert(0,deployment_server());self.server.grid(row=2,column=0,sticky='ew',ipady=9,pady=(6,14))
        tk.Label(form,text='Código temporal',font=('Segoe UI Semibold',10),fg=TEXT,bg=CARD).grid(row=3,column=0,sticky='w')
        self.code=tk.Entry(form,font=('Consolas',14),relief='solid',bd=1);self.code.grid(row=4,column=0,sticky='ew',ipady=9,pady=(6,7))
        hint='Déjalo vacío para diagnosticar y reparar la instalación existente.' if self.existing else 'Genera el código en HyperLogs; vence en 10 minutos.'
        self.hint=tk.Label(form,text=hint,font=('Segoe UI',9),fg=MUTED,bg=CARD,wraplength=430,justify='left');self.hint.grid(row=5,column=0,sticky='w')
        self.status=tk.Label(form,text='El instalador contiene el agente, el certificado y la configuración del servidor.',font=('Segoe UI',9),fg=MUTED,bg=CARD,wraplength=430,justify='left');self.status.grid(row=6,column=0,sticky='ew',pady=(18,10))
        buttons=tk.Frame(form,bg=CARD);buttons.grid(row=7,column=0,sticky='ew',pady=(4,20));buttons.columnconfigure(0,weight=1)
        self.repair=tk.Button(buttons,text='Diagnosticar y reparar',font=('Segoe UI Semibold',10),fg=TEXT,bg='#eeeeF2',activebackground='#e1e1e6',bd=0,cursor='hand2',command=lambda:self.start(True));self.repair.grid(row=0,column=0,sticky='w',ipadx=15,ipady=10)
        if not self.existing:self.repair.configure(state='disabled')
        self.button=tk.Button(buttons,text='Conectar e instalar',font=('Segoe UI Semibold',10),fg='white',bg=BLUE,activebackground='#0062c3',activeforeground='white',bd=0,cursor='hand2',command=lambda:self.start(False));self.button.grid(row=0,column=1,sticky='e',ipadx=18,ipady=10)
        checks=tk.Frame(shell,bg='#fafafa',highlightbackground='#ebebef',highlightthickness=1);checks.grid(row=3,column=1,sticky='nsew',padx=(0,40),pady=(0,22));checks.columnconfigure(0,weight=1)
        tk.Label(checks,text='COMPROBACIONES',font=('Segoe UI Semibold',9),fg=MUTED,bg='#fafafa').grid(row=0,column=0,sticky='w',padx=20,pady=(20,10))
        for index,label in enumerate(STEPS,1):
            row=tk.Frame(checks,bg='#fafafa');row.grid(row=index,column=0,sticky='ew',padx=20,pady=7);row.columnconfigure(1,weight=1)
            mark=tk.Label(row,text='○',font=('Segoe UI Semibold',13),fg='#a0a0a7',bg='#fafafa');mark.grid(row=0,column=0,padx=(0,10))
            text=tk.Label(row,text=label,font=('Segoe UI',10),fg=TEXT,bg='#fafafa');text.grid(row=0,column=1,sticky='w');self.rows[label]=(mark,text)
        self.protocol('WM_DELETE_WINDOW',self.close)

    def close(self):
        if not self.busy:self.destroy()

    def set_step(self,label,state,detail=''):
        def update():
            mark,text=self.rows[label];mark.configure(text={'running':'◌','ok':'✓','warn':'!','error':'×'}.get(state,'○'),fg={'running':BLUE,'ok':GREEN,'warn':'#a66a00','error':RED}.get(state,'#a0a0a7'));text.configure(text=label+((' · '+detail) if detail else ''))
        self.after(0,update)

    def start(self,repair):
        if self.busy:return
        if not repair and not self.code.get().strip():self.status.configure(text='Escribe el código temporal generado en HyperLogs.',fg=RED);return
        self.request_server=self.server.get().strip();self.request_code=self.code.get().strip()
        self.busy=True;self.button.configure(state='disabled');self.repair.configure(state='disabled');self.status.configure(text='Preparando una instalación verificable…',fg=BLUE)
        for mark,text in self.rows.values():mark.configure(text='○',fg='#a0a0a7');text.configure(text=text.cget('text').split(' · ')[0])
        threading.Thread(target=self.work,args=(repair,),daemon=True).start()

    def work(self,repair):
        try:
            agent=resource('HyperLogsAgent.exe');certificate=resource('caddy-root.crt');server=self.request_server
            self.set_step('Paquete integrado','running')
            if not agent.is_file() or not certificate.is_file():raise RuntimeError('El instalador está incompleto. Descárgalo nuevamente desde HyperLogs.')
            self.set_step('Paquete integrado','ok','agente y CA incluidos')
            self.set_step('Conectividad y TLS','running');server_health(server,certificate);self.set_step('Conectividad y TLS','ok','servidor saludable')
            plan=install_windows(agent,dry_run=True)
            if repair:
                self.set_step('Identidad del equipo','running');repair_config(plan['config'],server,plan['ca_cert']);self.set_step('Identidad del equipo','ok','credencial conservada')
            else:
                self.set_step('Identidad del equipo','running');result=claim(server,self.request_code,self.info,ca_cert=certificate);cfg=make_config(server,result['token'],plan['root'],ca_cert=plan['ca_cert']);write_config(plan['config'],cfg);self.set_step('Identidad del equipo','ok',result['name'])
            self.set_step('Permisos y archivos','running');install_windows(agent,ca_certificate=certificate,start_task=False);self.set_step('Permisos y archivos','ok','carpeta protegida')
            self.set_step('Auditoría de Windows','running');audited=enable_windows_auditing();self.set_step('Auditoría de Windows','ok' if audited else 'warn','inicios de sesión activos' if audited else 'requiere política local')
            self.set_step('Envío de prueba','running');output=run_agent_once(plan['binary'],plan['config']);count=output.split('Acknowledged events:',1)[1].splitlines()[0].strip();self.set_step('Envío de prueba','ok',count+' evento(s) aceptados')
            self.set_step('Inicio automático','running');start_windows_task();self.set_step('Inicio automático','ok','tarea en ejecución');self.after(0,lambda:self.success(repair))
        except Exception as exc:
            message=friendly_error(exc);self.after(0,lambda:self.failure(message))

    def success(self,repair):
        self.busy=False;self.status.configure(text='Diagnóstico completo. El equipo está enviando información a HyperLogs.',fg=GREEN);self.button.configure(state='normal',text='Finalizar',command=self.destroy);self.repair.configure(state='normal');messagebox.showinfo('HyperLogs listo','La instalación fue reparada y verificada.' if repair else 'La instalación fue verificada de extremo a extremo.')

    def failure(self,message):
        self.busy=False;self.status.configure(text=message,fg=RED);self.button.configure(state='normal',text='Intentar de nuevo',command=lambda:self.start(False));self.repair.configure(state='normal' if self.existing else 'disabled')


if __name__=='__main__':Setup().mainloop()
