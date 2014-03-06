--This script was created by T3CHKOMMIE. It is released under the GNU GPL lisense
--This script has been designed as a forensics tool to compensate for the lack of
--development of the TCPdSTAT tool. Use it on previously captured PCAP files to 
--analyze 7 protocols that are common in intrusions and attacks. This script looks
--to SNORT for examples. Thresholds can be set to flag protocols when they reach
--a certain percentage value. Everything is done by percentages. It is recommended
--to use this script on a PCAP file collected on a firewall or similar device in 
--a specific network topology. It is also recommended to use this tool to gain an
--understanding and "baseline" of your network so that you can better identify
--network abnormalities by protocol. 


--Confirmed working with Windows x-64 v 1.8.6
--not sure if it will work on x86 platforms or older versions.

--Not all protocols have been implemented. Wireshark limitations prevent massive 
--development of this script with regards to the automation and TVB buffer size.

--Use this tool to quickly search PCAP files for typical signs of intrusion. 
--Use this tool to quickly optain baseline measurements of network by protocol.

-- this only works in Wireshark
if not gui_enabled() then return end

-- range limits for protocols in percents


-- rating lowest threshhold. Thus, if TelnetT1 is set to 3, "warnings" we begin when telnet is above 3% of total packet transfer but below telnet2 which is the min. threshhold for DANGER!
--      Suspcious    |    Warning    |   to Danger and beyond

local irct0 = 0 local irct1 = 1 local irct2 = 2
local httpt0 = 50 local httpt1 = 70 local httpt2 = 80
local arpt0 = 1 local arpt1 = 3 local arpt2 = 5
local telnett0 = 0 local telnett1 = 1 local telnett2 = 3
local icmpt0 = 1 local icmpt1 = 2 local icmpt2 = 3
local smtpt0 = 0 local smtpt1 = 1 local smtpt2 = 2
local ssht0 = 0 local ssht1 = 1 local ssht2 = 3
local ftpt0 = 1 local ftpt1 = 3 local ftpt2 = 5




--local ip_packets = 0
local tcp_packets = 0
local http_packets = 0
local ssl_packets = 0
local squid_packets = 0
local smtp_packets = 0
local snmp_packets = 0
local aatp_packets = 0
local ftp_packets = 0
local pop3_packets = 0
local telnet_packets = 0
local ssh_packets = 0
local irc_packets = 0

local udp_packets = 0
local dns_packets = 0
local bgp_packets = 0 
local rip_packets = 0
local arp_packets = 0

local icmp_packets = 0
local igmp_packets = 0
local ospf_packets = 0
local ipip_packets = 0
local ipv6_packets = 0
local frag_packets = 0
local total_packets = 0
-- smtp, ftp, telnet, ssh, arp, icmp
local smtp_ips =""
local ftp_ips = ""
local telnet_ips =""
local ssh_ips =""
local arp_ips =""
local icmp_ips =""
local irc_ips = ""
local http_ips = ""
local results_log =""
local transfer_ftp_data_size = 0
local transfer_ssh_size = 0
local transfer_http_size = 0
local output = ""    -- for the output we'll show in the text window
local tw = nil       -- the text window
-- function to refresh the text window

local function  clearCounts()
          --  local ip_packets = 0
            local tcp_packets = 0
            local http_packets = 0
            local ssl_packets = 0
            local squid_packets = 0
            local smtp_packets = 0
            local snmp_packets = 0
            local aatp_packets = 0
            local ftp_packets = 0
            local pop3_packets = 0
            local telnet_packets = 0
            local ssh_packets = 0
            local irc_packets = 0

            local udp_packets = 0
            local dns_packets = 0
            local bgp_packets = 0 
            local rip_packets = 0
            local arp_packets = 0

            local icmp_packets = 0
            local igmp_packets = 0
            local ospf_packets = 0
            local ipip_packets = 0
            local ipv6_packets = 0
            local frag_packets = 0
            local total_packets = 0
            -- smtp, ftp, telnet, ssh, arp, icmp
            local smtp_ips =""
            local ftp_ips = ""
            local telnet_ips =""
            local ssh_ips =""
            local arp_ips =""
            local icmp_ips =""
            local irc_ips = ""
            local results_log =""
            local output = ""    -- for the output we'll show in the text window
            local tw = nil  


end



local function updateWindow()
    if tw then tw:set(output) end
end

-- calling tostring() on random FieldInfo's can cause an error, so this func handles it
local function getstring(finfo)
    local ok, val = pcall(tostring, finfo)
    if not ok then val = "(unknown)" end
    return val
end
    
-- create a new protocol so we can register a post-dissector
local myproto = Proto("TCPdShark","A modified port of TCPdSTAT for wireshark")

local function getFlag(prp, per)
        flag =""
-- smtp, ftp, telnet, irc,  ssh, arp, icmp
            
            if prp == "irc" then
                if irct0 < per and per < irct1    then
                    flag = "S"
                    results_log = results_log .. "\n\nSuspicious IRC activity detected. Manual inspection of IRC traffic recommended.\nInvolved Address(es) are:"..irc_ips
                elseif irct1 <= per and per <  irct2 then
                    flag = "W"
                    results_log = results_log .. "\n\nHigh volume of IRC activity detected. This could reflect a compromised device connected to a botnet.\nInvolved Address(es) are:"..irc_ips
                elseif irct2 <= per then
                    flag = "D"
                    results_log = results_log .. "\n\nDangerous amount of IRC activity detected. There is a high probability there is a botnet client on your network.\nInvolved Address(es) are:"..irc_ips
                
                else       
                flag = " "
                end

                elseif prp == "http" then
                    if transfer_http_size > 0 then
                        results_log = results_log .. "\n\n[HTTP] Bytes Transfered: " .. tostring((((transfer_http_size)/1024)/1024))  .." MB."
                    end
                if httpt0 < per and per <  httpt1 then
                    flag = "S"
                    results_log = results_log .. "\n\nSuspicious HTTP activity detected. Manual inspection of HTTP traffic recommended.\nInvolved Address(es) are:"..http_ips
                elseif httpt1 <= per and per <  httpt2 then
                    flag = "W"
                    results_log = results_log .. "\n\nHigh volume of HTTP activity detected.\nInvolved Address(es) are:"..http_ips
                elseif httpt2 <= per then
                    flag = "D"
                    results_log = results_log .. "\n\nDangerous amount of HTTP activity detected.\nInvolved Address(es) are:"..http_ips
                
                else       
                flag = " "
                end

            elseif prp == "arp" then
                if arpt0 < per and per <  arpt1 then
                    flag = "S"
                    results_log = results_log .. "\n\nSuspicious ARP activity detected. Manual inspection of ARP traffic recommended.\nInvolved Address(es) are:"..arp_ips
                elseif arpt1 <= per and per <  arpt2 then
                    flag = "W"
                    results_log = results_log .. "\n\nHigh volume of ARP activity detected. This could reflect a Man in the Middle attack attempt.\nInvolved Address(es) are:"..arp_ips
                elseif arpt2 <= per then
                    flag = "D"
                    results_log = results_log .. "\n\nDangerous amount of ARP activity detected. There is a high probability a hacker has attempted to ARP poison your network.\nInvolved Address(es) are:"..arp_ips
                
                else       
                flag = " "
                end

            elseif prp == "telnet" then
                if telnett0 < per and per <  telnett1 then
                    flag = "S"
                    results_log = results_log .. "\n\nSuspicious TELNET activity detected. Manual inspection of TELNET traffic recommended.\nInvolved Address(es) are:"..telnet_ips
                elseif telnett1 <= per and per <  telnett2 then
                    flag = "W"
                    results_log = results_log .. "\n\nHigh volume of TELNET activity detected. This could reflect a compromised device being controlled or phoning home.\nInvolved Address(es) are:"..telnet_ips
                elseif telnett2 <= per then
                    flag = "D"
                    results_log = results_log .. "\n\nDangerous amount of TELNET activity detected. There is a high probability there is a compromised device on your network.\nInvolved Address(es) are:"..telnet_ips
                
                else       
                flag = " "
                end
            elseif prp == "icmp" then
                if icmpt0 < per and per <  icmpt1 then
                    flag = "S"
                    results_log = results_log .. "\n\nSuspicious ICMP activity detected. Manual inspection of ICMP traffic recommended..\nInvolved Address(es) are:"..icmp_ips
                elseif icmpt1 <= per and per <  icmpt2 then
                    flag = "W"
                    results_log = results_log .. "\n\nHigh volume of ICMP activity detected. This could reflect a network scan.\nInvolved Address(es) are:"..icmp_ips
                elseif icmpt2 <= per then
                    flag = "D"
                    results_log = results_log .. "\n\nDangerous amount of ICMP activity detected. There is a high probability a hacker is performing network reconnaissance.\nInvolved Address(es) are:"..icmp_ips
                
                else       
                flag = " "
                end
            elseif prp == "smtp" then
                if smtpt0 < per and per <  smtpt1 then
                    flag = "S"
                    results_log = results_log .. "\n\nSuspicious SMTP activity detected. Manual inspection of SMTP traffic recommended.\nInvolved Address(es) are:"..smtp_ips
                elseif smtpt1 <= per and per <  smtpt2 then
                    flag = "W"
                    results_log = results_log .. "\n\nHigh volume of SMTP activity detected. This could reflect a hacker sending Spam from a device on your network.\nInvolved Address(es) are:"..smtp_ips
                elseif smtpt2 <= per then
                    flag = "D"
                    results_log = results_log .. "\n\nDangerous amount of SMTP activity detected. There is a high probability a machine on your network is sending Spam.\nInvolved Address(es) are:"..smtp_ips
                
                else       
                flag = " "
                end
            elseif prp == "ssh" then
                if transfer_ssh_size > 0 then                 --no 0.965 overhead calcuation ssh traffice not ssh-data. Not possible to tell what is transfer or commands.
                results_log = results_log .. "\n\n[SSH] Bytes Transfered: " .. tostring((((transfer_ssh_size)/1024)/1024))  .." MB."
                end

                if ssht0 < per and per <  ssht1 then
                    flag = "S"
                    results_log = results_log .. "\n\nSuspicious SSH activity detected. Manual inspection of SSH traffic recommended.\nInvolved Address(es) are:"..ssh_ips
                elseif ssht1 <= per and per <  ssht2 then
                    flag = "W"
                    results_log = results_log .. "\n\nHigh volume of SSH activity detected. This could reflect a compromised device controlled by a hacker.\nInvolved Address(es) are:"..ssh_ips
                elseif ssht2 <= per then
                    flag = "D"
                    results_log = results_log .. "\n\nDangerous amount of SSH activity detected. There is a high probability there is a remote controlled client on your network.\nInvoled Address(es) are:"..ssh_ips
                
                else       
                flag = " "
                end
            elseif prp == "ftp" then
                if transfer_ftp_data_size > 0 then                                                                        --not perfect but very close to account for packet overhead
                results_log = results_log .. "\n\n[FTP] Bytes Transfered: " .. tostring((((transfer_ftp_data_size*0.965)/1024)/1024))  .." MB."
                end

                if ftpt0 < per and per <  ftpt1 then
                    flag = "S"
                    results_log = results_log .. "\n\nSuspicious FTP activity detected. Manual inspection of FTP traffic recommended.\nInvolved Address(es) are:"..ftp_ips
                elseif ftpt1 <= per and per <  ftpt2 then
                    flag = "W"
                    results_log = results_log .. "\n\nHigh volume of FTP activity detected. This could reflect an intruder stealing data.\nInvolved Address(es) are:"..ftp_ips
                elseif ftpt2 <= per then
                    flag = "D"
                    results_log = results_log .. "\n\nDangerous amount of FTP activity detected. There is a high probability large amounts of data have left your network.\nInvoled Address(es) are:"..ftp_ips
                
                else       
                flag = " "
                end
            else
            flag = " "
        end
        
        return flag

end

-- the dissector function callback
local function getPercent(p)
    --p = tostring(prots)
        local Flag =""         
            if p == "total" then
                    percentage = ((total_packets/total_packets)*100)
                    Flag =  getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t    "..p.."\t\t"..total_packets.." ("..temp..")\n"



           -- elseif p == "ip" then
                    --percentage = ((ip_packets/total_packets)*100)
                    --Flag = getFlag(p, percentage)
                    --temp = tostring(percentage)
                    --temp = string.sub(temp,1,5) .."%"
                    --return "  [ "..Flag.." ]\t    "..p.."\t\t\t"..ip_packets.." ("..temp..")\n"



            elseif p == "tcp" then
                    percentage = ((tcp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t     "..p.."\t\t"..tcp_packets.." ("..temp..")\n"


            elseif p == "http" then
                    percentage = ((http_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..http_packets.." ("..temp..")\n"


            elseif p == "ssl" then
                    percentage = ((ssl_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..ssl_packets.." ("..temp..")\n"


            elseif p == "squid" then
                   percentage = ((squid_packets/total_packets)*100)
                   Flag = getFlag(p, percentage)
                   temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..squid_packets.." ("..temp..")\n"


            elseif p == "smtp" then
                    percentage = ((smtp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..smtp_packets.." ("..temp..")\n"


            elseif p == "snmp" then    
                    percentage = ((snmp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..snmp_packets.." ("..temp..")\n"


            elseif p == "aatp" then
                    percentage = ((aatp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..aatp_packets.." ("..temp..")\n"


            elseif p == "ftp" then
                    percentage = ((ftp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..ftp_packets.." ("..temp..")\n"
                                        

            elseif p == "pop3" then
                    percentage = ((pop3_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..pop3_packets.." ("..temp..")\n"


            elseif p == "telnet" then
                    percentage = ((telnet_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..telnet_packets.." ("..temp..")\n"


            elseif p == "ssh" then
                    percentage = ((ssh_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..ssh_packets.." ("..temp..")\n"
            

            elseif p == "irc" then
                    percentage = ((irc_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..irc_packets.." ("..temp..")\n"


            elseif p == "udp" then
                    percentage = ((udp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t     "..p.."\t\t"..udp_packets.." ("..temp..")\n"


            elseif p == "dns" then
                    percentage = ((dns_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..dns_packets.." ("..temp..")\n"


            elseif p == "bgp" then
                    percentage = ((bgp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..bgp_packets.." ("..temp..")\n"


            elseif p == "rip" then
                    percentage = ((rip_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..rip_packets.." ("..temp..")\n"


            elseif p == "arp" then
                    percentage = ((arp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t      "..p.."\t\t"..arp_packets.." ("..temp..")\n"


            elseif p == "icmp" then
                    percentage = ((icmp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t     "..p.."\t\t"..icmp_packets.." ("..temp..")\n"


            elseif p == "igmp" then
                    percentage = ((igmp_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t     "..p.."\t\t"..igmp_packets.." ("..temp..")\n"


            elseif p == "ospf" then
                    percentage = ((ospf_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t     "..p.."\t\t"..ospf_packets.." ("..temp..")\n"


            elseif p == "ipip" then
                    percentage = ((ipip_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t     "..p.."\t\t"..ipip_packets.." ("..temp..")\n"


            elseif p == "ipv6" then
                    percentage = ((ipv6_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t     "..p.."\t\t"..ipv6_packets.." ("..temp..")\n"


            elseif p == "frag" then
                    percentage = ((frag_packets/total_packets)*100)
                    Flag = getFlag(p, percentage)
                    temp = tostring(percentage)
                    temp = string.sub(temp,1,5) .."%"
                    return "  [ "..Flag.." ]\t     "..p.."\t\t"..frag_packets.." ("..temp..")\n"


            else

      return "Something bad happened!\n"
            end

           
end



function myproto.dissector(tvb,pinfo,tree)
    -- this if needs to stay outside of the loop
        
        --if pinfo.number > total_packets then
        --         total_packets = pinfo.number
        --end
    -- get a table of all FieldInfo objects
        local fields = { all_field_infos() }
        for ix, finfo in ipairs(fields) do
        --output = output .. "\n" ..finfo.name .. " = ".. getstring(finfo)
        -- set_color_filter_slot(index, dfilter)
        -- Change color of packets that are "bad"    

                --if finfo.name == "ip" then
                    --ip_packets = ip_packets + 1
                total_packets = total_packets + 1
                if finfo.name == "tcp" then
                    tcp_packets = tcp_packets + 1
                elseif finfo.name == "http" then
                    transfer_http_size = transfer_http_size + tonumber(pinfo.len)
                    if not string.find(http_ips, tostring(pinfo.src)) then
                        http_ips = http_ips.."\n\t"..getstring(pinfo.src)
                    end
                    http_packets = http_packets + 1
                elseif finfo.name == "ssl" then
                    ssl_packets = ssl_packets + 1
                elseif finfo.name == "squid" then
                    squid_packets = squid_packets + 1
                elseif finfo.name == "smtp" then
                    ip = getstring(pinfo.src)
                    --this is not working :(
                    if not string.find(smtp_ips, tostring(pinfo.src)) then
                        smtp_ips = smtp_ips.."\n\t"..getstring(pinfo.src)
                    end
                    smtp_packets = smtp_packets + 1
                elseif finfo.name == "snmp" then    
                    snmp_packets = snmp_packets + 1
                elseif finfo.name == "aatp" then
                    aatp_packets = aatp_packets + 1
                elseif finfo.name == "ftp" then
                    ip = getstring(pinfo.src)
                    if not string.find(ftp_ips, tostring(pinfo.src)) then
                        ftp_ips = ftp_ips.."\n\t"..getstring(pinfo.src)
                    end
                    ftp_packets = ftp_packets + 1
                elseif finfo.name == "ftp-data" then
                    ip = getstring(pinfo.src)
                    transfer_ftp_data_size = transfer_ftp_data_size + tonumber(pinfo.len)
                    if not string.find(ftp_ips, tostring(pinfo.src)) then
                        ftp_ips = ftp_ips.."\n\t"..getstring(pinfo.src)
                    end
                    ftp_packets = ftp_packets + 1
                elseif finfo.name == "pop3" then
                    pop3_packets = pop3_packets + 1
                elseif finfo.name == "telnet" then
                     ip = getstring(pinfo.src)
                    --this is not working :(
                    if not string.find(telnet_ips, tostring(pinfo.src)) then
                        telnet_ips = telnet_ips.."\n\t"..getstring(pinfo.src)
                    end
                    telnet_packets = telnet_packets + 1
                elseif finfo.name == "ssh" then
                    ip = getstring(pinfo.src)
                    transfer_ssh_size = transfer_ssh_size + tonumber(pinfo.len)
                    --this is not working :(
                    if not string.find(ssh_ips, tostring(pinfo.src)) then
                        ssh_ips = ssh_ips.."\n\t"..getstring(pinfo.src)
                    end
                    ssh_packets = ssh_packets + 1
                elseif finfo.name == "dns" then
                    dns_packets = dns_packets + 1
                elseif finfo.name == "bgp" then
                    bgp_packets = bgp_packets + 1
                elseif finfo.name == "irc" then
                    ip = getstring(pinfo.src)
                    --this is not working :(
                    if not string.find(irc_ips, tostring(pinfo.src)) then
                        irc_ips = irc_ips.."\n\t"..getstring(pinfo.src)
                    end 
                    irc_packets = irc_packets + 1
                elseif finfo.name == "udp" then
                    udp_packets = udp_packets + 1
                elseif finfo.name == "rip" then
                    rip_packets =  rip_packets + 1
                elseif finfo.name == "arp" then
                     ip = getstring(pinfo.src)
                    --this is not working :(
                    if not string.find(arp_ips, tostring(pinfo.src)) then
                        arp_ips = arp_ips.."\n\t"..getstring(pinfo.src)
                    end
                    arp_packets = arp_packets + 1
                elseif finfo.name == "icmp" then
                     ip = getstring(pinfo.src)
                    --this is not working :(
                    if not string.find(icmp_ips, tostring(pinfo.src)) then
                        icmp_ips = icmp_ips.."\n\t"..getstring(pinfo.src)
                    end
                    icmp_packets = icmp_packets + 1
                elseif finfo.name == "igmp" then
                    igmp_packets = igmp_packets + 1
                elseif finfo.name == "ospf" then
                    ospf_packets = ospf_packets + 1
                elseif finfo.name == "ipip" then
                    ipip_packets = ipip_packets + 1
                elseif finfo.name == "ipv6" then
                    ipv6_packets = ipv6_packets + 1
                elseif finfo.name == "frag" then
                    frag_packets = frag_packets + 1
                else

      
                end
                
        end

    --    if total_packets < pinfo.number then
         total_packets = tcp_packets + http_packets + ssl_packets + squid_packets + smtp_packets + snmp_packets + aatp_packets+ ftp_packets + pop3_packets + telnet_packets + ssh_packets + irc_packets + udp_packets + dns_packets + bgp_packets + rip_packets + arp_packets + icmp_packets + igmp_packets + ospf_packets + ipip_packets + ipv6_packets + frag_packets    
        -- total_packets = pinfo.number
        --end
    updateWindow()
end
-- register our new dummy protocol for post-dissection
register_postdissector(myproto)




-- now we create the menu function for this, which creates a text window to display this stuff
local function menu_view_tree()
    --clearCounts()
    set_filter("nbns")
    apply_filter()
    set_filter("")
    apply_filter()
    
    tw = TextWindow.new("TCPdShark: Report | Version 1.1.0")
    --tw:clear()
    tw:set_atclose(function() tw = nil end)
    
    output =   output ..    "\n******* Analysis Number: "..os.time().." *******\n"
    output =   output ..    "\nFLAG KEY :\n\"S\" - Suspicious\n\"W\" - Warning\n\"D\" - Danger\n"
    output =   output ..    "|  FLAG  |    Protocol    |     Packets    |\n"
    output =  output .. "--------------------------------------------\n".. getPercent('total').. getPercent('tcp') .. getPercent('http').. getPercent('squid').. getPercent('smtp').. getPercent('snmp').. getPercent('aatp').. getPercent('ftp')..  getPercent('pop3').. getPercent('telnet').. getPercent('ssh').. getPercent('irc').. getPercent('udp').. getPercent('dns').. getPercent('bgp').. getPercent('rip').. getPercent('arp').. getPercent('icmp').. getPercent('igmp').. getPercent('ospf').. getPercent('ipip').. getPercent('ipv6').. getPercent('frag')
    output = output .. "\n\nResult:\nAccording to the TCPdShark scan for this instance of packets, the following recommendations have been made:"
    output = output .. results_log
    output = output.."\n\n********** End Of Analysis **********"

    updateWindow()

end

local function dialog_menu(Protocols)

    utils = string.lower(Protocols)

    local function HTTP_dialog_func(Suspicious, Warning, Danger)
        httpt0 = tonumber(Suspicious)
        httpt1 = tonumber(Warning)
        httpt2 = tonumber(Danger)
        menu_view_tree()
    end
    local function IRC_dialog_func(Suspicious, Warning, Danger)
        irct0 = tonumber(Suspicious)
        irct1 = tonumber(Warning)
        irct2 = tonumber(Danger)
        menu_view_tree()
    end
    local function ARP_dialog_func(Suspicious, Warning, Danger)
        arpt0 = tonumber(Suspicious)
        arpt1 = tonumber(Warning)
        arpt2 = tonumber(Danger)
        menu_view_tree()
    end
    local function TELNET_dialog_func(Suspicious, Warning, Danger)
        telnett0 = tonumber(Suspicious)
        telnett1 = tonumber(Warning)
        telnett2 = tonumber(Danger)
        menu_view_tree()
    end
    local function SSH_dialog_func(Suspicious, Warning, Danger)
        ssht0 = tonumber(Suspicious)
        ssht1 = tonumber(Warning)
        ssht2 = tonumber(Danger)
        menu_view_tree()
    end
    local function FTP_dialog_func(Suspicious, Warning, Danger)
        ftpt0 = tonumber(Suspicious)
        ftpt1 = tonumber(Warning)
        ftpt2 = tonumber(Danger)
        menu_view_tree()
    end
    local function ICMP_dialog_func(Suspicious, Warning, Danger)
        icmpt0 = tonumber(Suspicious)
        icmpt1 = tonumber(Warning)
        icmpt2 = tonumber(Danger)
        menu_view_tree()
    end
    local function SMTP_dialog_func(Suspicious, Warning, Danger)
        smtpt0 = tonumber(Suspicious)
        smtpt1 = tonumber(Warning)
        smtpt2 = tonumber(Danger)
        menu_view_tree()
    end
     
    if string.find(utils, "http") then
    new_dialog("Adjust the thresholds for HTTP analysis in percentage",HTTP_dialog_func,"Suspicious", "Warning", "Danger")
    end
    if string.find(utils, "irc") then
    new_dialog("Adjust the thresholds for IRC analysis in percentage",IRC_dialog_func,"Suspicious", "Warning", "Danger")
    end
    if string.find(utils, "arp") then
    new_dialog("Adjust the thresholds for ARP analysis in percentage",ARP_dialog_func,"Suspicious", "Warning", "Danger")
    end
    if string.find(utils, "telnet") then
    new_dialog("Adjust the thresholds for TELNET analysis in percentage",TELNET_dialog_func,"Suspicious", "Warning", "Danger")
    end
    if string.find(utils, "ssh") then
    new_dialog("Adjust the thresholds for SSH analysis in percentage",SSH_dialog_func,"Suspicious", "Warning", "Danger")
    end
    if string.find(utils, "ftp") then
    new_dialog("Adjust the thresholds for FTP analysis in percentage",FTP_dialog_func,"Suspicious", "Warning", "Danger")
    end
    if string.find(utils, "icmp") then
    new_dialog("Adjust the thresholds for ICMP analysis in percentage",ICMP_dialog_func,"Suspicious", "Warning", "Danger")
    end
    if string.find(utils, "smtp") then
    new_dialog("Adjust the thresholds for SMTP analysis in percentage",SMTP_dialog_func,"Suspicious", "Warning", "Danger")
    end

end


local function choose_dialog_menu(Would)
    answer = string.lower(Would)

    if answer == "y" or answer =="yes" then
        new_dialog("Type the Protocols to set filter for",dialog_menu,"Protocols")
    else
        menu_view_tree()
    end

end

local function choose_dialog_menu_default()
    
    
    new_dialog("Default settings?",choose_dialog_menu,"Would you like to configure your own ranges for each protocol? y/n")

end


-- add this to the Tools->Lua submenu
register_menu("TCPdShark", choose_dialog_menu_default, MENU_TOOLS_UNSORTED)
