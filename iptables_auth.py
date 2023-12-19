
import os
import sys
import json
import subprocess
import argparse





def main():
	
	iptables_auth = "/usr/local/iptables_auth/repo"
	
	parser = argparse.ArgumentParser(description='iptables_auth')

	parser.add_argument('-u', '--update',  action='store_true', help='update iptables_auth')
	parser.add_argument('-d', '--delete',  action='store_true', help='delete user ip')
	parser.add_argument('-a', '--add',     action='store_true', help='add user ip')
	parser.add_argument('-c', '--cleanup', action='store_true', help='cleanup user rules')
	parser.add_argument('-i', '--init',    action='store_true', help='init deny rules')
	
	args = parser.parse_args()
    
	if args.update:
		os.system("cd " + iptables_auth + "; git pull")
		exit(0)

	if args.delete:
		del_user_rules()
		exit(0)
	
	if args.add:
		add_user_rules()
		exit(0)
	
	if args.cleanup:
		cleanup_user_rules()
		exit(0)
	
	if args.init:
		init_user_rules()
		exit(0)


# Extrahiere die IP-Adresse des SSH-Benutzers

def get_ports():

	if not os.path.exists( "/etc/iptables_auth.conf"):
		return []
	
	with open('/etc/iptables_auth.conf', 'r') as f:
		data = json.load(f)
		
	if not "ports" in data:
		return []
		
	return data["ports"]

def get_ports_combined():
	data = get_ports()
	return list(set(data['udp'] + data['tcp']))

def del_rule( ssh_ip, proto , p ):

	print("    Port {0}".format(p))

	cmd = "iptables -L INPUT --line-numbers -n"
	#print( cmd )

	# diese schleife muss sein weil das iptabled -D immer nur eine rule löscht
	# wenn die durch einen fehler merhfach drin ist ( ssh wurde terminiert )
	# werden sonst nicht alle gelöscht die der ip zugeordnet sind
	for i in range( 0 , 100):

			ret = subprocess.getstatusoutput( cmd )
			if ret[0] != 0:
					break

			for l in ret[1].split("\n"):

				if not "/* Dynamic User Rule */" in l:
					  continue

				if not "{0}".format( proto ) in l:
					  continue
					  
				if not "{0}".format( p ) in l:
					  continue

				if not "{0}".format( ssh_ip ) in l:
					  continue
				
				

				iptables_rule="iptables -D INPUT -p {0} --dport {1} -s {2} -j ACCEPT -m comment --comment \"Dynamic User Rule\""
				cmd2 = iptables_rule.format( proto , p, ssh_ip)
				print( cmd2 )
				os.system( cmd2 )
				
				break
def del_user_rules():
	
	ssh_ip=subprocess.getstatusoutput("who -m --ips | awk '{print $5}'")[1]

	print( "Delete User IP : " + ssh_ip )

	for p in get_ports()["udp"]:
		
		del_rule( ssh_ip, "udp", p )
	
	for p in get_ports()["tcp"]:
		
		del_rule( ssh_ip, "tcp", p )
		
			


	sys.exit( 0 )


def add_user_rules():

	ssh_ip=subprocess.getstatusoutput("who -m --ips | awk '{print $5}'")[1]

	print( "Allow User IP : " + ssh_ip  + " Ports : " + str( get_ports() ))
	
	
	iptables_rule="iptables -I INPUT 1 -p {0} --dport {1} -s {2} -j ACCEPT -m comment --comment \"Dynamic User Rule\""

	for p in get_ports()["udp"]:
			cmd = iptables_rule.format( "udp", p, ssh_ip)
			#print( cmd )
			os.system( cmd )
	
	for p in get_ports()["tcp"]:
			cmd = iptables_rule.format("tcp", p, ssh_ip)
			#print( cmd )
			os.system( cmd )


def cleanup_user_rules():

	cmd = "iptables -L INPUT --line-numbers -n | grep \"Dynamic User Rule\" | awk '{print $1}'"
	print( cmd )

	# die schleife muss sein weil die rule nummern sich immer verschieben und man sonst die falsche löscht
	for i in range( 0 , 1000):

			ret = subprocess.getstatusoutput( cmd )
			if ret[0] != 0:
					break
			print( ret[1] )

			rule_numbers=ret[1].split("\n")
			#print(rule_numbers)

			if len( rule_numbers ) <= 0 or len( rule_numbers[0] ) == 0 :
					break;

			cmd2 = "iptables -D INPUT {0}".format( rule_numbers[0] )
			print( cmd2 )
			os.system( cmd2 )

def init_user_rules():
	
	for p in get_ports()["tco"]:
		cmd = "iptables -A INPUT -p tcp --dport {0} -j REJECT --reject-with tcp-reset -m comment --comment \"Auth Reject Rule\"".format( p )
		print( cmd )
		os.system( cmd )
		
		cmd = "ip6tables -A INPUT -p tcp --dport {0} -j REJECT --reject-with tcp-reset -m comment --comment \"Auth Reject Rule\"".format( p )
		print( cmd )
		os.system( cmd )
	
	for p in get_ports()["udp"]:
		cmd = "iptables -A INPUT -p udp --dport {0} -j REJECT --reject-with tcp-reset -m comment --comment \"Auth Reject Rule\"".format( p )
		print( cmd )
		os.system( cmd )
		
		cmd = "ip6tables -A INPUT -p udp --dport {0} -j REJECT --reject-with tcp-reset -m comment --comment \"Auth Reject Rule\"".format( p )
		print( cmd )
		os.system( cmd )
	
	
