#!/usr/bin/env python3
from pyfiglet import Figlet
import datetime
import argparse
from scapy.all import *
import logging
from ReadRules import *
from Sniffer import *
import sys
sys.tracebacklimit = 0
from subprocess import DEVNULL, STDOUT, check_call




def main():

	now = datetime.datetime.now()
	print_banner()
	print("\n")
	args = vars(args_parser())
	arg = args_parser()
	rules_file = args['file']
	log_dir = args['logdir']
	pcap_file = args['pcap']
	interface = args['interface']
	
	if pcap_file != None and interface != None:
		raise Exception(colored("you cant specify an interface and a pcap file at the same time","red"))
	if log_dir==None:
		log_dir='.'
	filename = log_dir+"/Network-Shredder_" + str(now).replace(' ','-') + ".log"
	logging.basicConfig(filename=filename , format='%(asctime)s %(name)-4s %(levelname)-4s %(message)s',level=logging.INFO)

	print(colored("Blockarch started.", 'green'))

	print(colored("Reading Rules File "+rules_file+"...", "orange"))

	rules_list = readrules(rules_file)

	print(colored(" done reading rules' file ...", "green"))
	counter_rules = []
	timers = []
	for rule in rules_list:
		if "count" in rule.keys():
			counter_rules.append([0,int(rule["count"])])
		if "time" in rule.keys():
			timers.append([0,int(rule["time"])])

	if arg.quiet:
		if pcap_file == None:
			sniffer = Sniffer(rules_list=rules_list,interface=interface,pcap_file=None,quiet=True, counters=counter_rules, timers=timers)
			sniffer.start()

		else:
			sniffer = Sniffer(rules_list=rules_list,pcap_file=pcap_file,interface=None,quiet=True, counters=counter_rules, timers=timers)
			sniffer.start()
	else:
		if pcap_file == None:
			sniffer = Sniffer(rules_list=rules_list,interface=interface,pcap_file=None,quiet=False, counters=counter_rules, timers=timers)
			sniffer.start()

		else:
			sniffer = Sniffer(rules_list=rules_list,pcap_file=pcap_file,interface=None,quiet=False, counters=counter_rules, timers=timers)
			sniffer.start()



def print_banner():

	fig = Figlet(font="doh")
	banner = fig.renderText("BlockArch")
	print(colored(banner, 'red'))
	print(colored("|_ Usage :",'red',attrs=['bold']),colored(" python3 blockarch.py rules.txt","blue"))



def args_parser():
	parser = argparse.ArgumentParser()
    	parser.add_argument('--pcap', help='PCAP file to analyze')
    	parser.add_argument('--rfile', help='Rules file')
    	parser.add_argument('--logdir', help='specify Log Directory full path')
    	parser.add_argument('--interface', help='Interface to Sniff')
    	parser.add_argument('--quiet', help='Quiet Mode', action="store_true")
    	return parser.parse_args()

main()
