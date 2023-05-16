print('Murt - Lab 4')


from scapy.all import *
import argparse
import pcapy
import re
import base64
import codecs
import ipaddress

count = 0
username = ""

def packetcallback(packet):
  try:
    global count
    global username
    # The following is an example of Scapy detecting HTTP traffic
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts
    #if packet[TCP].dport == 80:
      #print("HTTP (web) traffic detected!")

#1. Xmas scan *WORKING*
    if packet[TCP].flags == "F" + "P" + "U":
        print("ALERT #" + str(count) + ": XMAS scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count += 1

#2. NULL scan *WORKING*  
    if packet[TCP].flags == 0:
        print("ALERT #" + str(count) + ": NULL scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        
        count += 1

#3. FIN scan *WORKING*
    if packet[TCP].flags == "F":
        print("ALERT #" + str(count) + ": FIN scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1  
        
    data = str(packet[Raw].load)
        
#4. Usernames and passwords sent in-the-clear via HTTP, FTP, and IMAP *WORKING*
    if "Authorization: Basic" in data: 
        r = re.compile("Authorization: Basic (.*)")
        b64 = re.search(r, data).group(1)   
        re.sub('[^A-Za-z0-9]+','',b64)
        
        b64 = b64.replace("\\r\\n","")
        b64 = b64[:-1]
        b64_decode = str(base64.b64decode(b64))
        
        decodeli = list(b64_decode.split(":"))
        
        usernameauth = str(decodeli[0][2:])
        passwordauth = str(decodeli[1][:-1])
        print("ALERT #" + str(count) + ": Usernames and passwords sent in-the-clear (" + str(packet[TCP].dport) + ")" + " (username: " + usernameauth + ", password: " + passwordauth + ")") 
        count +=1

    if "USER" in data:
        usernameli = list(data.split(" "))
        username = str(usernameli[1]).replace("\\r\\n", "")
        re.sub('[^A-Za-z0-9]+','',username)
        username = username[:-1]

    if "PASS" in data:
        passli = list(data.split(" "))
        password = passli[1].replace("\\r\\n", "")
        password = password[:-1]
        print("ALERT #" + str(count) + ": Usernames and passwords sent in-the-clear (" + str(packet[TCP].dport) + ")" + " (username: " + username + ", password: " + password + ")") 
        count +=1

#5. Nikto scan *WORKING*
    if "Nikto" in data:
        print("ALERT #" + str(count) + ": Nikto scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count += 1

#6. Server Message Block (SMB) scan       
    if packet[TCP].dport == 139 or packet[TCP].dport == 445 or packet[TCP].sport == 139 or packet[TCP].sport == 445:            
        print("ALERT #" + str(count) + ": SMB scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count += 1        
        
        
  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")