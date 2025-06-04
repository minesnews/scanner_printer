#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Программа для снятия счетчиков с сетевых принтеров
Поддерживает SNMP, HTTP/Web-интерфейс и другие методы
"""

import socket
import requests
import re
import json
import csv
from datetime import datetime
import subprocess
import sys
import urllib3
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

# Отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PrinterCounterReader:
    def __init__(self):
        self.timeout = 5
        self.counters = {}
        
        # SNMP OID для различных счетчиков принтеров
        self.snmp_oids = {
            'total_pages': '1.3.6.1.2.1.43.10.2.1.4.1.1',
            'black_pages': '1.3.6.1.2.1.43.10.2.1.4.1.2',
            'color_pages': '1.3.6.1.2.1.43.10.2.1.4.1.3',
            'duplex_pages': '1.3.6.1.2.1.43.10.2.1.4.1.4',
            'total_impressions': '1.3.6.1.2.1.43.10.2.1.4.1.1',
            'device_name': '1.3.6.1.2.1.1.5.0',
            'device_description': '1.3.6.1.2.1.1.1.0',
            'device_uptime': '1.3.6.1.2.1.1.3.0'
        }
    
    def snmp_get(self, ip, community='public', oid=None):
        """SNMP запрос (упрощенная реализация без pysnmp)"""
        try:
            # Простая реализация SNMP GET через snmpget (если установлен)
            if oid:
                cmd = ['snmpget', '-v2c', '-c', community, ip, oid]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                if result.returncode == 0:
                    # Парсим результат
                    output = result.stdout.strip()
                    if '=' in output:
                        value = output.split('=', 1)[1].strip()
                        # Убираем типы данных SNMP
                        value = re.sub(r'^[A-Za-z\s]*:\s*', '', value)
                        value = value.strip('"')
                        return value
        except Exception as e:
            pass
        return None
    
    def snmp_walk(self, ip, community='public', oid=None):
        """SNMP walk для получения множественных значений"""
        try:
            cmd = ['snmpwalk', '-v2c', '-c', community, ip, oid]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout*2)
            if result.returncode == 0:
                values = {}
                for line in result.stdout.strip().split('\n'):
                    if '=' in line:
                        oid_part, value_part = line.split('=', 1)
                        value = value_part.strip()
                        value = re.sub(r'^[A-Za-z\s]*:\s*', '', value)
                        values[oid_part.strip()] = value.strip('"')
                return values
        except Exception as e:
            pass
        return {}
    
    def read_snmp_counters(self, ip, community='public'):
        """Чтение счетчиков через SNMP"""
        print(f"Попытка чтения счетчиков через SNMP с {ip}...")
        counters = {}
        
        for counter_name, oid in self.snmp_oids.items():
            value = self.snmp_get(ip, community, oid)
            if value:
                counters[counter_name] = value
                print(f"  {counter_name}: {value}")
        
        # Дополнительные счетчики через walk
        try:
            # Счетчики страниц
            page_counters = self.snmp_walk(ip, community, '1.3.6.1.2.1.43.10.2.1.4')
            for oid, value in page_counters.items():
                if value.isdigit():
                    counters[f"pages_{oid.split('.')[-1]}"] = value
        except:
            pass
        
        return counters
    
    def read_http_counters(self, ip, username=None, password=None):
        """Чтение счетчиков через HTTP/веб-интерфейс"""
        print(f"Попытка чтения счетчиков через HTTP с {ip}...")
        counters = {}
        
        # Список возможных URL для различных принтеров
        urls_to_try = [
            f'http://{ip}/',
            f'http://{ip}/status',
            f'http://{ip}/printer/status',
            f'http://{ip}/cgi-bin/dynamic/printer/status.html',
            f'http://{ip}/hp/device/info_device',
            f'http://{ip}/DevMgmt/ProductUsageDyn.xml',
            f'http://{ip}/DevMgmt/ConsumableConfigDyn.xml',
            f'http://{ip}/PageCountChip/TotalPageCount.xml',
            f'https://{ip}/',
            f'https://{ip}/status',
        ]
        
        session = requests.Session()
        if username and password:
            session.auth = (username, password)
        
        for url in urls_to_try:
            try:
                response = session.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Поиск счетчиков в HTML/XML
                    counters.update(self.parse_web_content(content, url))
                    
                    if counters:
                        print(f"  Найдены счетчики на {url}")
                        break
                        
            except Exception as e:
                continue
        
        return counters
    
    def parse_web_content(self, content, url):
        """Парсинг веб-контента для поиска счетчиков"""
        counters = {}
        
        # Регулярные выражения для поиска различных счетчиков
        patterns = {
            'total_pages': [
                r'total.*?pages.*?(\d+)',
                r'page.*?count.*?(\d+)',
                r'impressions.*?(\d+)',
                r'totalpagecount.*?(\d+)',
                r'>(\d+)</.*?total',
            ],
            'black_pages': [
                r'black.*?pages.*?(\d+)',
                r'mono.*?pages.*?(\d+)',
                r'b&w.*?pages.*?(\d+)',
            ],
            'color_pages': [
                r'color.*?pages.*?(\d+)',
                r'colour.*?pages.*?(\d+)',
            ],
            'duplex_pages': [
                r'duplex.*?pages.*?(\d+)',
                r'double.*?sided.*?(\d+)',
            ]
        }
        
        for counter_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    # Берем последнее найденное значение (обычно самое релевантное)
                    value = matches[-1]
                    if value.isdigit():
                        counters[counter_type] = int(value)
                        break
        
        # Специальная обработка XML контента
        if 'xml' in url.lower() or content.strip().startswith('<?xml'):
            try:
                xml_counters = self.parse_xml_counters(content)
                counters.update(xml_counters)
            except:
                pass
        
        return counters
    
    def parse_xml_counters(self, xml_content):
        """Парсинг XML для поиска счетчиков"""
        counters = {}
        try:
            root = ET.fromstring(xml_content)
            
            # Поиск различных тегов со счетчиками
            for elem in root.iter():
                tag_lower = elem.tag.lower()
                if elem.text and elem.text.isdigit():
                    if 'page' in tag_lower or 'count' in tag_lower or 'impression' in tag_lower:
                        counters[f"xml_{elem.tag}"] = int(elem.text)
        except:
            pass
        
        return counters
    
    def read_jetdirect_counters(self, ip, port=9100):
        """Чтение счетчиков через JetDirect (порт 9100)"""
        print(f"Попытка чтения счетчиков через JetDirect {ip}:{port}...")
        counters = {}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # PJL команды для получения информации
            commands = [
                b'\x1b%-12345X@PJL\r\n',
                b'@PJL INFO ID\r\n',
                b'@PJL INFO PAGECOUNT\r\n',
                b'@PJL INQUIRE PAGECOUNT\r\n',
                b'@PJL INFO USTATUS\r\n',
                b'\x1b%-12345X\r\n'
            ]
            
            for cmd in commands:
                sock.send(cmd)
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Парсим ответ
            lines = response.split('\n')
            for line in lines:
                if 'PAGECOUNT' in line.upper():
                    match = re.search(r'(\d+)', line)
                    if match:
                        counters['jetdirect_pagecount'] = int(match.group(1))
                        
        except Exception as e:
            pass
        
        return counters
    
    def read_all_counters(self, ip, methods=['snmp', 'http', 'jetdirect'], 
                         snmp_community='public', http_user=None, http_pass=None):
        """Чтение счетчиков всеми доступными методами"""
        print(f"\nЧтение счетчиков с принтера {ip}")
        print("="*50)
        
        all_counters = {
            'ip': ip,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'methods_used': [],
            'counters': {}
        }
        
        if 'snmp' in methods:
            try:
                snmp_counters = self.read_snmp_counters(ip, snmp_community)
                if snmp_counters:
                    all_counters['methods_used'].append('SNMP')
                    all_counters['counters'].update(snmp_counters)
            except Exception as e:
                print(f"Ошибка SNMP: {e}")
        
        if 'http' in methods:
            try:
                http_counters = self.read_http_counters(ip, http_user, http_pass)
                if http_counters:
                    all_counters['methods_used'].append('HTTP')
                    all_counters['counters'].update(http_counters)
            except Exception as e:
                print(f"Ошибка HTTP: {e}")
        
        if 'jetdirect' in methods:
            try:
                jetdirect_counters = self.read_jetdirect_counters(ip)
                if jetdirect_counters:
                    all_counters['methods_used'].append('JetDirect')
                    all_counters['counters'].update(jetdirect_counters)
            except Exception as e:
                print(f"Ошибка JetDirect: {e}")
        
        return all_counters
    
    def print_counters(self, counter_data):
        """Вывод счетчиков на экран"""
        print(f"\nРезультаты для {counter_data['ip']}:")
        print(f"Время: {counter_data['timestamp']}")
        print(f"Методы: {', '.join(counter_data['methods_used'])}")
        print("-" * 40)
        
        if not counter_data['counters']:
            print("Счетчики не найдены")
            return
        
        for counter_name, value in counter_data['counters'].items():
            print(f"{counter_name:20}: {value}")
    
    def save_to_csv(self, counter_data, filename=None):
        """Сохранение счетчиков в CSV файл"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"printer_counters_{timestamp}.csv"
        
        file_exists = False
        try:
            with open(filename, 'r'):
                file_exists = True
        except FileNotFoundError:
            pass
        
        with open(filename, 'a', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['ip', 'timestamp', 'methods_used'] + list(counter_data['counters'].keys())
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            if not file_exists:
                writer.writeheader()
            
            row_data = {
                'ip': counter_data['ip'],
                'timestamp': counter_data['timestamp'],
                'methods_used': ', '.join(counter_data['methods_used'])
            }
            row_data.update(counter_data['counters'])
            writer.writerow(row_data)
        
        print(f"Данные сохранены в {filename}")
    
    def save_to_json(self, counter_data, filename=None):
        """Сохранение счетчиков в JSON файл"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"printer_counters_{timestamp}.json"
        
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            data = []
        
        data.append(counter_data)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"Данные сохранены в {filename}")

def main():
    reader = PrinterCounterReader()
    
    print("Программа для снятия счетчиков сетевых принтеров")
    print("="*50)
    
    # Ввод IP адреса
    ip = input("Введите IP адрес принтера: ").strip()
    
    # Выбор методов
    print("\nДоступные методы:")
    print("1. SNMP (требует snmpget/snmpwalk)")
    print("2. HTTP/Web-интерфейс")
    print("3. JetDirect (порт 9100)")
    print("4. Все методы")
    
    method_choice = input("Выберите метод (1-4): ").strip()
    
    methods = ['snmp', 'http', 'jetdirect']
    if method_choice == '1':
        methods = ['snmp']
    elif method_choice == '2':
        methods = ['http']
    elif method_choice == '3':
        methods = ['jetdirect']
    
    # Дополнительные параметры
    snmp_community = 'public'
    http_user = None
    http_pass = None
    
    if 'snmp' in methods:
        community = input(f"SNMP community (по умолчанию '{snmp_community}'): ").strip()
        if community:
            snmp_community = community
    
    if 'http' in methods:
        use_auth = input("Требуется авторизация для веб-интерфейса? (y/n): ").strip().lower()
        if use_auth == 'y':
            http_user = input("Имя пользователя: ").strip()
            http_pass = input("Пароль: ").strip()
    
    # Чтение счетчиков
    counter_data = reader.read_all_counters(
        ip, methods, snmp_community, http_user, http_pass
    )
    
    # Вывод результатов
    reader.print_counters(counter_data)
    
    # Сохранение
    save_choice = input("\nСохранить результаты? (csv/json/n): ").strip().lower()
    if save_choice == 'csv':
        reader.save_to_csv(counter_data)
    elif save_choice == 'json':
        reader.save_to_json(counter_data)

if __name__ == "__main__":
    main()