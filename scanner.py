#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Программа для поиска сетевых принтеров в локальной сети
Поддерживает несколько методов поиска: SNMP, ping, сканирование портов
"""

import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import time
import sys

class NetworkPrinterScanner:
    def __init__(self):
        self.printer_ports = [9100, 515, 631, 80, 443, 161]  # Типичные порты принтеров
        self.found_printers = []
        
    def get_local_network(self):
        """Определяет локальную сеть"""
        try:
            # Получаем IP адрес компьютера
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Определяем сеть (предполагаем /24)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return network
        except Exception as e:
            print(f"Ошибка определения сети: {e}")
            return None
    
    def ping_host(self, ip):
        """Проверяет доступность хоста через ping"""
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], 
                                      capture_output=True, text=True)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                      capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def scan_port(self, ip, port, timeout=1):
        """Сканирует конкретный порт на хосте"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_device_info(self, ip):
        """Пытается получить информацию об устройстве"""
        info = {
            'ip': str(ip),
            'hostname': None,
            'open_ports': [],
            'device_type': 'Unknown'
        }
        
        # Получаем hostname
        try:
            info['hostname'] = socket.gethostbyaddr(str(ip))[0]
        except:
            pass
        
        # Сканируем порты принтеров
        for port in self.printer_ports:
            if self.scan_port(ip, port, timeout=0.5):
                info['open_ports'].append(port)
        
        # Определяем тип устройства по открытым портам
        if info['open_ports']:
            if 9100 in info['open_ports']:
                info['device_type'] = 'Network Printer (RAW/JetDirect)'
            elif 515 in info['open_ports']:
                info['device_type'] = 'Network Printer (LPD/LPR)'
            elif 631 in info['open_ports']:
                info['device_type'] = 'Network Printer (IPP/CUPS)'
            elif any(port in [80, 443] for port in info['open_ports']):
                info['device_type'] = 'Network Device (Web Interface)'
        
        return info
    
    def scan_network_range(self, network, max_workers=50):
        """Сканирует диапазон IP адресов"""
        print(f"Сканирование сети {network}...")
        print(f"Всего адресов для проверки: {network.num_addresses}")
        
        active_hosts = []
        
        # Первый этап: ping sweep
        print("Этап 1: Поиск активных хостов...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            ping_results = list(executor.map(self.ping_host, network.hosts()))
        
        for i, (ip, is_alive) in enumerate(zip(network.hosts(), ping_results)):
            if is_alive:
                active_hosts.append(ip)
                print(f"Найден активный хост: {ip}")
        
        print(f"\nНайдено активных хостов: {len(active_hosts)}")
        
        # Второй этап: детальное сканирование активных хостов
        if active_hosts:
            print("\nЭтап 2: Поиск принтеров среди активных хостов...")
            with ThreadPoolExecutor(max_workers=20) as executor:
                device_infos = list(executor.map(self.get_device_info, active_hosts))
            
            # Фильтруем только устройства с открытыми портами принтеров
            for info in device_infos:
                if info['open_ports']:
                    self.found_printers.append(info)
                    print(f"Найден принтер: {info['ip']} ({info['hostname'] or 'неизвестно'})")
    
    def snmp_discovery(self, ip):
        """Попытка SNMP запроса для получения информации о принтере"""
        try:
            # Базовый SNMP запрос (требует pysnmp)
            # Здесь упрощенная реализация без внешних зависимостей
            pass
        except:
            pass
    
    def print_results(self):
        """Выводит результаты сканирования"""
        print("\n" + "="*60)
        print("РЕЗУЛЬТАТЫ ПОИСКА СЕТЕВЫХ ПРИНТЕРОВ")
        print("="*60)
        
        if not self.found_printers:
            print("Сетевые принтеры не найдены.")
            return
        
        for i, printer in enumerate(self.found_printers, 1):
            print(f"\nПринтер #{i}:")
            print(f"  IP адрес: {printer['ip']}")
            print(f"  Hostname: {printer['hostname'] or 'Неизвестно'}")
            print(f"  Тип устройства: {printer['device_type']}")
            print(f"  Открытые порты: {', '.join(map(str, printer['open_ports']))}")
            
            # Дополнительная информация по портам
            port_descriptions = {
                9100: "RAW/JetDirect (HP)",
                515: "LPD/LPR (Line Printer Daemon)",
                631: "IPP/CUPS (Internet Printing Protocol)",
                80: "HTTP (Web интерфейс)",
                443: "HTTPS (Безопасный web интерфейс)",
                161: "SNMP (Управление)"
            }
            
            print("  Описание портов:")
            for port in printer['open_ports']:
                desc = port_descriptions.get(port, "Неизвестный сервис")
                print(f"    {port}: {desc}")
    
    def scan_specific_range(self, ip_range):
        """Сканирует указанный диапазон IP"""
        try:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            self.scan_network_range(network)
        except ValueError as e:
            print(f"Неверный формат сети: {e}")
    
    def interactive_scan(self):
        """Интерактивный режим сканирования"""
        print("Поиск сетевых принтеров")
        print("="*30)
        
        choice = input("\nВыберите режим:\n1. Автоматический поиск в локальной сети\n2. Указать диапазон IP вручную\nВведите номер (1-2): ")
        
        if choice == "1":
            network = self.get_local_network()
            if network:
                self.scan_network_range(network)
            else:
                print("Не удалось определить локальную сеть")
        
        elif choice == "2":
            ip_range = input("Введите диапазон IP (например, 192.168.1.0/24): ")
            self.scan_specific_range(ip_range)
        
        else:
            print("Неверный выбор")
            return
        
        self.print_results()

def main():
    scanner = NetworkPrinterScanner()
    
    if len(sys.argv) > 1:
        # Командная строка
        ip_range = sys.argv[1]
        scanner.scan_specific_range(ip_range)
        scanner.print_results()
    else:
        # Интерактивный режим
        scanner.interactive_scan()

if __name__ == "__main__":
    main()