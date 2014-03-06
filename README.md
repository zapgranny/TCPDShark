TCPDShark
=========

This is a program that is based off of tcpdstat, and works as a plug-in for WireShark. It was originally created by T3CHKOMMIE, but I am fixing some of the bugs in the code. 


--This script was created by T3CHKOMMIE. It is released under the GNU GPL license
--This script has been designed as a forensics tool to compensate for the lack of
--development of the TCPdSTAT tool. Use it on previously captured PCAP files to 
--analyze 7 protocols that are common in intrusions and attacks. This script looks
--to SNORT for examples. Thresholds can be set to flag protocols when they reach
--a certain percentage value. Everything is done by percentages. It is recommended
--to use this script on a PCAP file collected on a firewall or similar device in 
--a specific network topology. It is also recommended to use this tool to gain a
--understanding and "baseline" of your network so that you can better identify
--network abnormalities by protocol. 


--Confirmed working with Windows x-64 v 1.8.6
--not sure if it will work on x86 platforms or older versions.

--Not all protocols have been implemented. WireShark limitations prevent massive 
--development of this script with regards to the automation and TVB buffer size.

--Use this tool to quickly search PCAP files for typical signs of intrusion. 
--Use this tool to quickly obtain baseline measurements of network by protocol.

-- this only works in WireShark
