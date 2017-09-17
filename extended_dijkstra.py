from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import inet
from ryu.lib.packet import ipv4
import requests
from requests.auth import HTTPDigestAuth
import json
import networkx as nx
from pprint import pprint
import thread
import time
from threading import Thread


class ExampleSwitch13(app_manager.RyuApp):

	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	PRIORITY1 = 11112
	flag1 = 1
	incr = 1
	G = nx.DiGraph();


	#NEW TOPOLOGY
	SSWlist = [227564574114628, 81795612149576];
	ServerInfolist = {227564574114628:{'server_ip':'192.168.1.11', 'server_mac':'fa:16:3e:00:6c:a8', 'port_bytes':0, 'port_byte_diff':0}, 81795612149576:{'server_ip':'192.168.1.12', 'server_mac':'fa:16:3e:00:5b:b3', 'port_bytes':0, 'port_byte_diff':0}}
	flow_time = time.time()
	SWITCH_TIMEOUT = 10
	SWITCH_IDLE_TIMEOUT = 10
	NODE_CAPACITY = 1000000
	curr_src = '10.10.10.10'
	ssw_monitor_flag = 1
	
	def __init__(self, *args, **kwargs):
		super(ExampleSwitch13, self).__init__(*args, **kwargs)
		# initialize mac address table.
		self.mac_to_port = {}
		t = Thread(target=self.server_switch_monitor)
		t.start()
		t1 = Thread(target=self.TopologyDiscovery)
		t1.start()
		
	####THREAD MONITORING NUMBER OF BYTES PASSING THROUGH SERVER-SWITCH AND SERVER LINK PER SECOND
	def server_switch_monitor(self):
		while 1:
			time.sleep(1)
			if self.ssw_monitor_flag == 1: #RUNNING THE INITIALIZATION PART
				time.sleep(3)
				#for dpid in SSWlist
				len_SSWlist = len(self.SSWlist) #length of SSW list
				for i in range(0, len_SSWlist, 1): #iterate 
					server_switch_str = str(self.SSWlist[i])
					
					url1 = "http://localhost:8080/stats/port/"
					url1 = url1 + server_switch_str
					myResponse1 = requests.get(url1)
					if(myResponse1.ok):
						jData1 = json.loads(myResponse1.content)
						val = 0
						len2 = len(jData1[server_switch_str])
						#print "\n\n Check 2.1 \n\n"
						port_no = 1
			
						for j in range(0, len2, 1):
							if int(jData1[server_switch_str][j]["port_no"]) == port_no:
								r_bytes = int(jData1[server_switch_str][j]["rx_bytes"])
								t_bytes = int(jData1[server_switch_str][j]["tx_bytes"])
								bcount_server_switch = r_bytes + t_bytes  ##Count of bytes tx and rx by PORT1 of SSW
								break
							else:
								continue				
						self.ServerInfolist[int(server_switch_str)]['port_bytes'] = bcount_server_switch
						#print "INITIALIZE {}: BYTES:{} DIFF_BYTES:{}".format(server_switch_str, self.ServerInfolist[int(server_switch_str)]['port_bytes'], self.ServerInfolist[int(server_switch_str)]['port_byte_diff'])
					
					
			else: #MODIFYING THINGS FOR EVERY SECOND
				#for dpid in SSWlist
				len_SSWlist = len(self.SSWlist) #length of SSW list
				for i in range(0, len_SSWlist, 1): #iterate 
					server_switch_str = str(self.SSWlist[i])
					
					url1 = "http://localhost:8080/stats/port/"
					url1 = url1 + server_switch_str
					myResponse1 = requests.get(url1)
					if(myResponse1.ok):
						jData1 = json.loads(myResponse1.content)
						val = 0
						len2 = len(jData1[server_switch_str])
						#print "\n\n Check 2.1 \n\n"
						port_no = 1
			
						for j in range(0, len2, 1):
							if int(jData1[server_switch_str][j]["port_no"]) == port_no:
								r_bytes = int(jData1[server_switch_str][j]["rx_bytes"])
								t_bytes = int(jData1[server_switch_str][j]["tx_bytes"])
								bcount_server_switch = r_bytes + t_bytes  ##Count of bytes tx and rx by PORT1 of SSW
								break
							else:
								continue
						prev_bytes = self.ServerInfolist[int(server_switch_str)]['port_bytes']
						bytes_diff = bcount_server_switch - prev_bytes			
						self.ServerInfolist[int(server_switch_str)]['port_bytes'] = bcount_server_switch
						self.ServerInfolist[int(server_switch_str)]['port_byte_diff'] = bytes_diff
					#print "MODIFYING {}: BYTES:{} DIFF_BYTES:{}".format(server_switch_str, self.ServerInfolist[int(server_switch_str)]['port_bytes'], self.ServerInfolist[int(server_switch_str)]['port_byte_diff'])
			
			self.ssw_monitor_flag = 0
		

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install the table-miss flow entry.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# construct flow_mod message and send it.
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		
			#DPID of SSW1, SSW2, SSW3
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# get Datapath ID to identify OpenFlow switches.
		DPID = datapath.id
		origin = datapath.id
		dpid = datapath.id
		#self.mac_to_port.setdefault(dpid, {})

		# analyse the received packets using the packet library.
		pkt = packet.Packet(msg.data)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		dst = eth_pkt.dst
		src = eth_pkt.src
		eth_type = eth_pkt.ethertype
		
		eth = pkt.get_protocols(ethernet.ethernet)[0]
		
		if eth_type == 0x88cc: #Ignore LLDP packets
			return

		if eth_type == 0x0806: #Ignore ARP packets
			return

		
		
		self.logger.info("Ether Type %s", eth_type)
		
		
		
		ip_pkt = pkt.get_protocol(ipv4.ipv4)
		IPV4_DST = ip_pkt.dst
		dst_ip = ip_pkt.dst
		IPV4_SRC = ip_pkt.src
		
		# get the received port number from packet_in message.
		IN_PORT = msg.match['in_port']
		in_port = msg.match['in_port']
		self.logger.info("packet in %s %s %s %s %s %s", DPID,IPV4_SRC,IPV4_DST, src, dst, IN_PORT)

		##Topology Discovery done only once
		
		
		if IPV4_DST != "192.168.1.10":
			return
		#	print "RETURNING "+IPV4_DST
		
		if self.incr == 1:
			self.curr_src = IPV4_SRC
			self.flow_time = time.time()
			#thread.start_new_thread(self.TopologyDiscovery(1))
			#print "\n\n\n\n\nCREATE THREAD {}\n\n\n\n\n".format(self.incr)
			self.incr = self.incr+1
			
			#time.sleep(5)
			
		
		else:

			new_flow_time = time.time()
			time_diff = new_flow_time - self.flow_time

			if (self.curr_src == IPV4_SRC) and (time_diff < 10):
				return
			else:
				self.flow_time = new_flow_time
				self.curr_src = IPV4_SRC
		

		print "\nSRC IP:"+IPV4_SRC+"  DST_IP:"+IPV4_DST


		#####CALCULATES SHORTEST PATH TO EACH SERVER AND STORE IN PATH_ALL LIST
		path_all = []
		path_len = []
		for destination in self.SSWlist:
			#print"\n PATH from {} to {}".format(origin, destination)
			if destination == origin:
				continue
			try:
				length = nx.dijkstra_path_length(self.G, origin, destination, 'weight')
				path = nx.dijkstra_path(self.G, origin, destination, 'weight')
				print "\nPATH and LENGTH FOR {}".format(destination)
				print path
				print length
				#print "\n"
				path_len.append(length)  #stores path length for each PATH
				path_all.append(path)  #stores path for reach each SSW
			except (nx.NetworkXNoPath, nx.NetworkXError):
				#print "Not found"
				continue
		#select shortest path from host to reach server
		
		
		
		
		#THRESHOLD CHECK
		len_SSWlist = len(self.SSWlist) #length of SSW list
		P = []
		P_cost = []
		Q = []
		Q_cost = []
		
		#print "\n\nLEN OF PATHALL {}\n\n".format(len(path_all))
		
		
		for i in range(0, len_SSWlist, 1): #iterate 
			check_path = path_all[i]
			path_len1 = len(check_path)
			server_switch = check_path[path_len1 -1] #This is the Server Switch to be VERIFIED
			
			server_switch_str = str(server_switch)
			if self.ServerInfolist[int(server_switch_str)]['port_byte_diff'] > 100000:
				 #print "HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
				 #print self.ServerInfolist[int(server_switch_str)]
				 if self.ServerInfolist[int(server_switch_str)]['server_ip']=='192.168.1.11':
				 	print "SERVER 1 RUNNING ABOVE THRESHOLD"
				 else:
				 	print "SERVER 2 RUNNING ABOVE THRESHOLD"
				 Q.append(check_path)
				 Q_cost.append(path_len[i])
			else:
				P.append(check_path)
				P_cost.append(path_len[i])

			

		#####LOAD BALANCING ENGINE#########	
		if len(P) != 0: #Check if some SERVER is running above THRESHOLD
			#print "\nBELOW SEREVR IS RUNNING BELOW THRESHOLD\n"
			pos = P_cost.index(min(P_cost))
			selpath = P[pos]
			print selpath[len(selpath)-1]
		
		else: #If all SSW are running above THRESHOLD then select min cost server from Q
			print "\n\nInside IF\n\n"
			pos = Q_cost.index(min(Q_cost))
			selpath = Q[pos]
				
		#pos = path_len.index(min(path_len))
		#selpath = path_all[pos]
		
		if selpath[len(selpath)-1] == 227564574114628:
			print selpath[len(selpath)-1]
			print "SELECTED SERVER1"
		else:
			print selpath[len(selpath)-1]
			print "SELECTED SERVER2"
		
		print "SELECTED PATH"
		print selpath
		print "\n"
		#write the flow for the selected path
		length = len(selpath)
		count = 0
		
		dpid = selpath[length-1]
		server_ip = self.ServerInfolist[dpid]['server_ip']


		#####TOWARDS FLOW WRITER#####
		for i in range(0,len(selpath),1):
			DPID = selpath[i]
			if count != 0: #we are at first switch in the path
				IN_PORT = int(self.G[selpath[i-1]][selpath[i]]['dst_port'])
				
			if count != length-1: #we are not at last switch in the path
				OUT_PORT = int(self.G[selpath[i]][selpath[i+1]]['src_port'])
				#print "\n\nADD PATH FLOW INPORT:{} OUTPORT:{}\n\n".format(IN_PORT, OUT_PORT)
				self.path_switch_add_flows(DPID, IN_PORT, IPV4_SRC, IPV4_DST, OUT_PORT, server_ip, self.PRIORITY1)
		
			if count == length-1: #we are at last switch in the path
				OUT_PORT = 1
				server_mac = self.ServerInfolist[DPID]['server_mac']
				self.server_switch_add_flows(DPID, IN_PORT, IPV4_SRC, IPV4_DST, OUT_PORT, server_ip, server_mac, self.PRIORITY1)
				#print "Server IP: ",self.ServerInfolist[DPID]['server_ip']
				#print "Server MAC: ",self.ServerInfolist[DPID]['server_mac']
			#print "Flow : ",DPID, IN_PORT, OUT_PORT
			self.PRIORITY1 = self.PRIORITY1 + 1
			count=count+1		
		


	
	#########ADDING FLOW TO SERVER SWITCH##############
	def server_switch_add_flows(self, dpid, in_port, ipv4_src, virtual_ip, out_port, server_ip, server_mac, PRIORITY1):

		url_add = 'http://localhost:8080/stats/flowentry/add'
		DPID = "dpid"
		HARD_TIMEOUT = "hard_timeout"
		COOKIE = "cookie"
		COOKIE_MASK = "cookie_mask"
		TABLE_ID = "table_id"
		IDLE_TIMEOUT = "idle_timeout"
		HARD_TIMEOUT = "hard_timeout"
		PRIORITY = "priority"
		FLAGS = "flags"
		MATCH = "match"
		IN_PORT = "in_port"
		ETH_TYPE = "eth_type"
		IPV4_SRC = "ipv4_src"
		IPV4_DST = "ipv4_dst"
		ACTIONS = "actions"
		TYPE = "type"
		FIELD = "field"
		VALUE = "value"
		PORT = "port"

		server_switch_to_server = dict.fromkeys([DPID, COOKIE, COOKIE_MASK, TABLE_ID, IDLE_TIMEOUT, HARD_TIMEOUT,PRIORITY, FLAGS, MATCH, ACTIONS])
		# Create empty match dictionary
		server_switch_to_server[MATCH] = dict.fromkeys([IN_PORT, ETH_TYPE, IPV4_SRC, IPV4_DST])
		server_switch_to_server[COOKIE] = 1
		server_switch_to_server[COOKIE_MASK] = 1
		server_switch_to_server[TABLE_ID] = 0
		server_switch_to_server[IDLE_TIMEOUT] = self.SWITCH_IDLE_TIMEOUT
		server_switch_to_server[HARD_TIMEOUT] = self.SWITCH_TIMEOUT
		server_switch_to_server[FLAGS] = 1
		# Create empty actions: You may create an empty dictionary for actions like above with all the possible 4 fields of actions, TYPE, FIELD, VALUE, PORT, and keep the unrequired None, if that is allowed by Ryu
		server_switch_to_server[ACTIONS] = []
		server_switch_to_server[ACTIONS].append(dict.fromkeys([TYPE, FIELD, VALUE]))
		server_switch_to_server[ACTIONS].append(dict.fromkeys([TYPE, FIELD, VALUE]))
		server_switch_to_server[ACTIONS].append(dict.fromkeys([TYPE, PORT]))


		arp_request= {'dpid': dpid,'cookie': 1,'cookie_mask': 1,'table_id': 0,'idle_timeout': self.SWITCH_IDLE_TIMEOUT,'hard_timeout': self.SWITCH_TIMEOUT,
	'priority': PRIORITY1,'flags': 1,'match':{'in_port':out_port,'eth_type':0x0806,'arp_spa':server_ip,'arp_tpa':ipv4_src,'arp_op':'1'},
	'actions':[{'type':"OUTPUT",'port':in_port}]}

		arp_reply= {'dpid': dpid,'cookie': 1,'cookie_mask': 1,'table_id': 0,'idle_timeout': self.SWITCH_IDLE_TIMEOUT,'hard_timeout': self.SWITCH_TIMEOUT,
	'priority': PRIORITY1,'flags': 1,'match':{'in_port':in_port,'eth_type':0x0806,'arp_spa':ipv4_src,'arp_tpa':server_ip,'arp_op':'2'},
	'actions':[{'type':"OUTPUT",'port':out_port}]}

		
		server_switch_to_server[DPID] = dpid
		server_switch_to_server[PRIORITY] = PRIORITY1
		server_switch_to_server[MATCH][IN_PORT] = in_port
		server_switch_to_server[MATCH][ETH_TYPE] = 0x0800
		server_switch_to_server[MATCH][IPV4_SRC] = ipv4_src
		server_switch_to_server[MATCH][IPV4_DST] = virtual_ip
		server_switch_to_server[ACTIONS][0][TYPE]= "SET_FIELD"
		server_switch_to_server[ACTIONS][0][FIELD] = "eth_dst"
		server_switch_to_server[ACTIONS][0][VALUE] = server_mac
		server_switch_to_server[ACTIONS][1][TYPE]= "SET_FIELD"
		server_switch_to_server[ACTIONS][1][FIELD] = "ipv4_dst"
		server_switch_to_server[ACTIONS][1][VALUE] = server_ip
		server_switch_to_server[ACTIONS][2][TYPE]= "OUTPUT"
		server_switch_to_server[ACTIONS][2][PORT] = out_port
		#print "\nServer Switch to server flow 1"
		#print(json.dumps(server_switch_to_server))
		r = requests.post(url_add,data=json.dumps(server_switch_to_server))
		server_switch_to_server[MATCH][IN_PORT] = out_port
		server_switch_to_server[MATCH][ETH_TYPE] = 0x0800
		server_switch_to_server[MATCH][IPV4_SRC] = server_ip
		server_switch_to_server[MATCH][IPV4_DST] = ipv4_src
		server_switch_to_server[ACTIONS][0][TYPE]= "SET_FIELD"
		server_switch_to_server[ACTIONS][0][FIELD] = "eth_src"
		server_switch_to_server[ACTIONS][0][VALUE] = "aa:aa:aa:aa:aa:aa"
		server_switch_to_server[ACTIONS][1][TYPE]= "SET_FIELD"
		server_switch_to_server[ACTIONS][1][FIELD] = "ipv4_src"
		server_switch_to_server[ACTIONS][1][VALUE] = virtual_ip
		server_switch_to_server[ACTIONS][2][TYPE]= "OUTPUT"
		server_switch_to_server[ACTIONS][2][PORT] = in_port
		#print "\nServer Switch to server flow 2"
		#print(json.dumps(server_switch_to_server))
		r = requests.post(url_add,data=json.dumps(arp_request))
		r = requests.post(url_add,data=json.dumps(arp_reply))
		r = requests.post(url_add,data=json.dumps(server_switch_to_server))
		
	

	#########ADDING FLOW TO PATH SWITCH#############
	def path_switch_add_flows(self, dpid, in_port, ipv4_src, virtual_ip, out_port, server_ip, PRIORITY1):

		url_add = 'http://localhost:8080/stats/flowentry/add'
		DPID = "dpid"
		HARD_TIMEOUT = "hard_timeout"
		COOKIE = "cookie"
		COOKIE_MASK = "cookie_mask"
		TABLE_ID = "table_id"
		IDLE_TIMEOUT = "idle_timeout"
		HARD_TIMEOUT = "hard_timeout"
		PRIORITY = "priority"
		FLAGS = "flags"
		MATCH = "match"
		IN_PORT = "in_port"
		ETH_TYPE = "eth_type"
		IPV4_SRC = "ipv4_src"
		IPV4_DST = "ipv4_dst"
		ACTIONS = "actions"
		TYPE = "type"
		FIELD = "field"
		VALUE = "value"
		PORT = "port"
		
		path_switch = dict.fromkeys([DPID, COOKIE, COOKIE_MASK, TABLE_ID, IDLE_TIMEOUT, HARD_TIMEOUT,PRIORITY, FLAGS, MATCH, ACTIONS])
		# Create empty match dictionary
		path_switch[MATCH] = dict.fromkeys([IN_PORT, ETH_TYPE, IPV4_SRC, IPV4_DST])
		path_switch[COOKIE] = 1
		path_switch[COOKIE_MASK] = 1
		path_switch[TABLE_ID] = 0
		path_switch[IDLE_TIMEOUT] = self.SWITCH_IDLE_TIMEOUT
		path_switch[HARD_TIMEOUT] = self.SWITCH_TIMEOUT
		path_switch[FLAGS] = 1
		# Create empty actions: You may create an empty dictionary for actions like above with all the possible 4 fields of actions, TYPE, FIELD, VALUE, PORT, and keep the unrequired None, if that is allowed by Ryu
		path_switch[ACTIONS] = []
		path_switch[ACTIONS].append(dict.fromkeys([TYPE, PORT]))



		arp_request= {'dpid': dpid,'cookie': 1,'cookie_mask': 1,'table_id': 0,'idle_timeout': self.SWITCH_IDLE_TIMEOUT,'hard_timeout': self.SWITCH_TIMEOUT,
	'priority': PRIORITY1,'flags': 1,'match':{'in_port':out_port,'eth_type':0x0806,'arp_spa':server_ip,'arp_tpa':ipv4_src,'arp_op':'1'},
	'actions':[{'type':"OUTPUT",'port':in_port}]}

		arp_reply= {'dpid': dpid,'cookie': 1,'cookie_mask': 1,'table_id': 0,'idle_timeout': self.SWITCH_IDLE_TIMEOUT,'hard_timeout': self.SWITCH_TIMEOUT,
	'priority': PRIORITY1,'flags': 1,'match':{'in_port':in_port,'eth_type':0x0806,'arp_spa':ipv4_src,'arp_tpa':server_ip,'arp_op':'2'},
	'actions':[{'type':"OUTPUT",'port':out_port}]}

	
		path_switch[DPID] = dpid
		path_switch[PRIORITY] = PRIORITY1
		path_switch[MATCH][IN_PORT] = in_port
		path_switch[MATCH][ETH_TYPE] = 0x0800
		path_switch[MATCH][IPV4_SRC] = ipv4_src
		path_switch[MATCH][IPV4_DST] = virtual_ip
		path_switch[ACTIONS][0][TYPE]= "OUTPUT"
		path_switch[ACTIONS][0][PORT] = out_port
		#print "\nPATH SWITCH flow 1"
		#print(json.dumps(path_switch))
		r = requests.post(url_add,data=json.dumps(path_switch))
		path_switch[MATCH][IN_PORT] = out_port
		path_switch[MATCH][ETH_TYPE] = 0x0800
		path_switch[MATCH][IPV4_SRC] = virtual_ip
		path_switch[MATCH][IPV4_DST] = ipv4_src
		path_switch[ACTIONS][0][TYPE]= "OUTPUT"
		path_switch[ACTIONS][0][PORT] = in_port
		#print "\nPATH SWITCH flow 2"
		#print(json.dumps(path_switch))
		r = requests.post(url_add,data=json.dumps(path_switch))
		r = requests.post(url_add,data=json.dumps(arp_request))
		r = requests.post(url_add,data=json.dumps(arp_reply))



	#######TOPOLOGY DISCOVERY ADDING NODES AND EDGES PER SECOND#######
	def TopologyDiscovery(self):
		time.sleep(8)
		while 1:
			#print "\n\nSWITCH DISCOVERY\n\n"
			url = "http://localhost:8080/v1.0/topology/switches"
			#print "\n\nTHREAD RUNNING\n\n"
			myResponse = requests.get(url)
			ts = time.time()
			
			if(myResponse.ok):
				jData = json.loads(myResponse.content)
				for data in jData:
					len1 = len(data["ports"])
					dpid1 = str(data["dpid"])
					dpid1_dec = int(dpid1, 16) #Switch dpid str value
					dpid1_dec_str = str(dpid1_dec)
					url1 = "http://localhost:8080/stats/port/"
					url1 = url1 + dpid1_dec_str
					myResponse1 = requests.get(url1)
					if(myResponse1.ok):
						jData1 = json.loads(myResponse1.content)
						val = 0
						len2 = len(jData1[dpid1_dec_str])
						for j in range(0, len2, 1):
							val = val + int(jData1[dpid1_dec_str][j]["rx_bytes"])
					if self.flag1== 1:
						self.G.add_node(dpid1_dec, weight=1, Bcount=val, DiffBcount=0, timestamp=ts, timestamp_diff=0)
					else:
						attr = nx.get_node_attributes(self.G, 'Bcount')
						diffBcount = val - attr[dpid1_dec]
						attr = nx.get_node_attributes(self.G, 'timestamp')
						timestamp_diff1 = ts - attr[dpid1_dec]
						
						self.G.add_node(dpid1_dec, weight=1, Bcount=val, DiffBcount=diffBcount, timestamp=ts, timestamp_diff=timestamp_diff1)
						
				if self.flag1 ==1:
					print "SWITCHES IN TOPOLOGY ARE"
					print self.G.nodes()
			
			else:
				print "SWITCH FAILED"

			###PERFORMING LINK DISCOVERY###
			url = "http://localhost:8080/v1.0/topology/links"
			myResponse = requests.get(url)
			if(myResponse.ok):
				#print "\n\nLINK DISCOVERY\n\n"
				#self.logger.info("Inside Link TopoDiscovery")
				jData = json.loads(myResponse.content)
				
				#print "\n\n"
				for data in jData:
					len1 = len(data["src"])
					src_dpid = str((data["src"]["dpid"]))
					src_dpid_dec = int(src_dpid, 16) #Switch dpid str value
					src_dpid_dec_str = str(src_dpid_dec)
					src_port = str(data["src"]["port_no"])
					dst_dpid = str(data["dst"]["dpid"])
					dst_dpid_dec = int(dst_dpid, 16) #Switch dpid str value
					dst_dpid_dec_str = str(dst_dpid_dec)
					dst_port = str(data["dst"]["port_no"])
					
					####DEFAULT BANDWIDTH FOR !)MB LINKS
					bandwidth1 = 1800000
					
					
					#SET Bandwidth for 100KB link
					if (src_dpid_dec==226605077397827 and dst_dpid_dec==81795612149576) or (src_dpid_dec==81795612149576 and dst_dpid_dec==226605077397827):
						bandwidth1 = 20000
					
					#SET Bandwidth for 1MB link
					if (src_dpid_dec==143396754488654 and dst_dpid_dec==227564574114628) or (src_dpid_dec==227564574114628 and dst_dpid_dec==143396754488654):
						bandwidth1 = 160000
					
					#SET Bandwidth for 1MB link
					if (src_dpid_dec==152793539598402 and dst_dpid_dec==236378474446153) or (src_dpid_dec==236378474446153 and dst_dpid_dec==152793539598402):
						bandwidth1 = 160000
					
					#print "\n\n Check 2 \n\n"
					
					url1 = "http://localhost:8080/stats/port/"
					url1 = url1 + dst_dpid_dec_str
					myResponse1 = requests.get(url1)
					if(myResponse1.ok):
						jData1 = json.loads(myResponse1.content)
						val = 0
						len2 = len(jData1[dst_dpid_dec_str])
						#print "\n\n Check 2.1 \n\n"
						port_no = int(dst_port)

						for j in range(0, len2, 1):
							if int(jData1[dst_dpid_dec_str][j]["port_no"]) == port_no:
								r_bytes = int(jData1[dst_dpid_dec_str][j]["rx_bytes"])
								t_bytes = int(jData1[dst_dpid_dec_str][j]["tx_bytes"])
								bcount_dst = r_bytes + t_bytes
								break
							else:
								continue				

					if self.flag1 == 1:
						#edge_weight = 1 + G[dst_dpid_dec]['weight']
						self.G.add_edge(src_dpid_dec, dst_dpid_dec, src_port=src_port, dst_port=dst_port, Bcount_dst=bcount_dst, DiffBcount=0, weight=0.5,bandwidth=bandwidth1, timestamp=ts)
					
					else :
						attr = nx.get_node_attributes(self.G, 'DiffBcount')
						diffBcount_dst = attr[dst_dpid_dec]  #Stores Diff of Bcount on DST on all ports (NODE COST)
						
						attr = nx.get_node_attributes(self.G, 'timestamp_diff')
						timestamp_diff = attr[dst_dpid_dec]  #Stores Diff of Bcount on DST on all ports (NODE COST)
						#timestamp_diff = ts - prev_timestamp
						weight1=0.0
						link_weight = float(float(diffBcount)/float(bandwidth1))
						dst_node_weight = 0.0
						dst_node_weight = (float(diffBcount_dst)/float(self.NODE_CAPACITY))
						#print "DIFFCOUNT {}".format(diffBcount)
						#print "DST_NODE_COUNT"
						#print dst_node_weight
						weight1 = float(link_weight + dst_node_weight)
						
						
						diffBcount = bcount_dst - self.G[src_dpid_dec][dst_dpid_dec]['Bcount_dst']   #Stores info of diff of Byte count on link port of DST (LINK COST)
						#print "EDGE {}->{} LINK COST:{} NODE COST:{} SUM:{}".format(src_dpid_dec,dst_dpid_dec, diffBcount, diffBcount_dst, float(link_weight), float(dst_node_weight), float(weight1))
						#print "EDGE", src_dpid_dec,"->",dst_dpid_dec, "LINK COST:", link_weight,"NODE COST", dst_node_weight,"SUMCOST:", weight1
						#print "WEIGHT %.5f" %weight1 
						#print weight1
						self.G.add_edge(src_dpid_dec, dst_dpid_dec, src_port=src_port, dst_port=dst_port, Bcount_dst=bcount_dst, DiffBcount=diffBcount, weight=weight1, bandwidth=bandwidth1, timestamp=ts)
			else:
				print "LINK FAILED"
				#myResponse.raise_for_status()

			#self.logger.info("\nAfter Link TopoDiscovery\n")
			if self.flag1 == 1:
				print "\nDISCOVERY COMPLETE\n"

			self.flag1 = 0
			time.sleep(1)			
