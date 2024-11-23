import json
import re 
import sys
import hashlib
import math
import time
import psutil
import os
from datetime import datetime, timezone
#------------------------------------------------------------------------------------------------
# format nasich logov COMBINED
###
# 83.149.9.216 - - 
# [17/May/2015:10:05:03 +0000] 
# "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 
# 200 
# 203023 
# "http://semicomplete.com/presentations/logstash-monitorama-2013/" 
# "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"

#TODO https://stackoverflow.com/questions/452104/is-it-worth-using-pythons-re-compile
#TODO https://stackoverflow.com/questions/12544510/parsing-apache-log-files
#TODO https://github.com/chandravanip/ApacheLogAnalyzerTool/blob/master/ApachehttpdLogParser.py
#TODO https://www.w3schools.com/python/python_regex.asp
#TODO https://ru.stackoverflow.com/questions/452676/%d0%a0%d0%b5%d0%b3%d1%83%d0%bb%d1%8f%d1%80%d0%bd%d0%be%d0%b5-%d0%b2%d1%8b%d1%80%d0%b0%d0%b6%d0%b5%d0%bd%d0%b8%d0%b5-%d0%b2%d0%b0%d0%bb%d0%b8%d0%b4%d0%b0%d1%86%d0%b8%d1%8f-%d1%81%d1%82%d1%80%d0%be%d0%ba%d0%b8-%d0%bb%d0%be%d0%b3%d0%b0-apache
logformat = re.compile(
    r'^(?P<ip>.*?)\s+-\s+-\s'  # IP-adresa klienta
    r'\[(?P<timestamp>[^\]]+)\]\s'  # datum aj cas
    r'"(?P<request>(\S+)\s(\S+)\s(HTTP/\d.\d))"\s' # metod, URL aj protokol
    r'(?P<status>\d{3})\s'  # status kod
    r'(?P<size>\d+|-)\s'  # velkost otazky
    r'"(?P<referrer>[^"]*)"\s' # Refer - odkial prisiel
    r'"(?P<user_agent>[^"]*)"' # User-Agent
)

#------------------------------------------------------------------------------------------------
#TODO https://stackoverflow.com/questions/78757328/log-file-selection-of-specific-log-content-inside-log-file-by-start-and-end-dat
def timeReturn(timestamp): 
    return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")#format casu: '17/May/2015:10:05:03 +0000'

# parsing casu  s uctom formatu
def timeFile(file, start, end):
    start1 = datetime.strptime(start, "%d/%b/%Y:%H:%M:%S %z")
    end1 = datetime.strptime(end, "%d/%b/%Y:%H:%M:%S %z")
    errorlog =[]
    f = open("resultDate.txt", "w+")
    errorLine = 0
    with open("resultDate.txt", "w") as f:
        f.write(f"Pre interval, od {start} do {end}:")
        f.write(f"\n")
        with open(file, 'r') as file:
            for i in file:
                match = logformat.match(i)
                if match != None:
                    timestamp = timeReturn(match["timestamp"])  # kontrolujem format casu
                    if start1 <= timestamp and end1>=timestamp:  # ak cas patri do intervala
                        f.write(f"-> {i.strip()}")
                        f.write(f"\n")
                else:
                    errorLine = errorLine + 1 
                    errorlog.append(i)
        
        if errorLine != 0 and errorLine > 0:# ak mame chybu vo formate, tak napiseme na koniec subora txt
            f.write(f"\n")
            f.write(f"Error: {errorLine} riadok nie je v spravnom formate")
            f.write(f"\n")
            for i in errorlog[:5]:  # vypiseme 5 chyb
                f.write(f"- {i.strip()}" )
                f.write(f"\n")

#------------------------------------------------------------------------------------------------
# parsing pre id=XXX....
def keyFile(file, key):
    errorlog =[]
    f = open("resultKey.txt", "w+")
    errorLine = 0
    with open("resultKey.txt", "w") as f:
        f.write(f"Pre parameter: {key}")
        f.write(f"\n")
        with open(file, 'r') as file:
            for i in file:
                match = logformat.match(i)
                if match != None: 
                    url = match['request'].split()[1] 
                    ipQuest = match['ip']
                    timeQuest = timeReturn(match["timestamp"]) 
                    # print(url)
                    # time.sleep(2)
                    if str(key) in str(url):
                        #print("!!!!!!!!: "+url)
                        #time.sleep(2)
                        # parameters = str(url.split("?")[1])
                        #print(f"параметры: {parameters}")
                        # if str(key) in str(parameters):
                        f.write(f"-> cesta:{url} - ip:{ipQuest} - time:{timeQuest}\n")  
                else:
                    errorLine = errorLine + 1 
                    errorlog.append(i)
            f.write(f'\n') 
        
        if errorLine != 0 and errorLine > 0:
            f.write(f"\n")
            f.write(f"Error: {errorLine} riadok nie je v spravnom formate")
            f.write(f"\n")
            for i in errorlog[:5]:  
                f.write(f"- {i.strip()}")
                f.write(f"\n")

#------------------------------------------------------------------------------------------------
#TODO https://www.youtube.com/watch?app=desktop&v=4DdueeIE8Rs
#TODO https://ru.stackoverflow.com/questions/1278714/%D0%9A%D0%B0%D0%BA-%D0%BD%D0%B0%D0%BF%D0%B8%D1%81%D0%B0%D1%82%D1%8C-%D0%BF%D0%B0%D1%80%D1%81%D0%B8%D0%BD%D0%B3-apache-access-log-%D1%81-%D1%80%D0%B5%D0%B7%D1%83%D0%BB%D1%8C%D1%82%D0%B0%D1%82%D0%BE%D0%BC-%D0%B2-json-%D1%84%D0%B0%D0%B9%D0%BB%D0%B5
#TODO https://ru.stackoverflow.com/questions/1280800/%D0%94%D0%BE%D1%81%D1%82%D0%B0%D1%82%D1%8C-10-%D1%81%D0%B0%D0%BC%D1%8B%D1%85-%D1%87%D0%B0%D1%81%D1%82%D1%8B%D1%85-%D0%B7%D0%B0%D0%BF%D1%80%D0%BE%D1%81%D0%BE%D0%B2-%D0%BF%D0%BE-ip-%D0%B8%D0%B7-access-log
def analyzeFile(log_file):
    
    requestCount = 0
    
    #pre kazdy parsing mame slovnik
    status = {} #pre status
    iplog = {} #pre ip
    useragent = {} #pre user agent
    referlink = {} #pre odkial prisiel
    
    errorLine = 0
    errorlog = []
    
    ip_url_counter = {}
    method_posit = {}
    status_with_link = {}
    status_with_link505 = {}

    all_logs = [] #celkovo

        
    with open(log_file, 'r+') as file:
        for l in file: 

            #TODO https://github.com/chandravanip/ApacheLogAnalyzerTool/blob/master/ApachehttpdLogParser.py#L18
            #TODO https://stackoverflow.com/questions/62689107/groupdict-in-regex
            match = logformat.match(l) 
            if match:
                match.groupdict()
            else:
                errorLine = errorLine+1 #ak chyba to napiseme tiez to
                errorlog.append(l)

            if match != None:
                all_logs.append(match)

                s = match['status'] #zoberieme z dict, a kontrolujem a pouzivam dalej
                # print(s)
                # time.sleep(2)
                if s in status:
                    status[s] =status[s] + 1
                else:
                    status[s] = 1 #нak nie je tak vytvorim = 1

                ip = match['ip']
                #print(ip)
                #print(type(ip))
                # time.sleep(2)
                if ip in iplog:
                    iplog[ip] =iplog[ip] + 1
                else:
                    iplog[ip] = 1

                refer = match['referrer']
                if refer in referlink:
                    referlink[refer] = referlink[refer]+1
                else:
                    referlink[refer]= 1

                uq = match['user_agent']
                if uq in useragent:
                    useragent[uq] =useragent[uq] + 1
                else:
                    useragent[uq] = 1
                
                url = match['request'].split()[1]  #druhy element od pregex
                ip = match['ip']
                ip_url = f"{ip} -> {url}"  # vytvorime spolu IP + URL

                
                if ip_url in ip_url_counter:
                    ip_url_counter[ip_url] =ip_url_counter[ip_url] + 1
                else:
                    ip_url_counter[ip_url] = 1

                #kolko bolo pre  Get, Post atd.
                method = match['request'].split()[0] #berieme prvy index -> "GET"....
                if method in method_posit:
                    method_posit[method] = method_posit[method]+1
                else:
                    method_posit[method] = 1

                sN = match['status']
                urlN = match['request'].split()[1] 
                # print(sN)
                # print(type(sN))
                # time.sleep(5)
                sNurl = f"{sN} -> {urlN}"
                if sNurl in status_with_link and sN == "404": 
                    status_with_link[sNurl] =status_with_link[sNurl] + 1
                elif sNurl not in status_with_link and sN == "404":
                    status_with_link[sNurl] = 1
                else:
                    pass

                sN2 = match['status']
                urlN2 = match['request'].split()[1] 
                # print(sN)
                # time.sleep(2)
                sNurl2 = f"{sN2} -> {urlN2}" #spojime pre 505- ake chyby na strane servera 
                if sNurl2 in status_with_link505 and sN2 == "505": 
                    status_with_link505[sNurl2] =status_with_link505[sNurl2] + 1
                elif sNurl2 not in status_with_link505 and sN2 == "505":
                    status_with_link505[sNurl2] = 1
                else:
                    pass

                

                requestCount =requestCount + 1

    return requestCount, status, iplog, useragent, referlink, all_logs, errorLine, errorlog, ip_url_counter, method_posit, status_with_link, status_with_link505

# vysledok do txt
def printToFile(allElement, RSstatus, RSip, RSuseragent, RSreferlink, errorLine, errorlog, all_logs, ip_url_counter, method_posit, status_with_link, status_with_link505):
    f = open("result.txt", "w+")
    table=[]
    f.write(f"Celkovy pocet ziadosti: {allElement}")
    f.write("\n")
    #print("-------------------------------------\n")
    #TODO https://sky.pro/wiki/python/dobavlyaem-novuyu-stroku-pri-zapisi-v-fayl-python-file-write/
    f.write("Top 10 IP adries (najvacsi):")
    f.write("\n")
    #print(RSip)
    #TODO https://www.freecodecamp.org/news/lambda-sort-list-in-python/
    #TODO https://stackoverflow.com/questions/613183/how-do-i-sort-a-dictionary-by-value
    sorted_ips = sorted(RSip.items(), key=lambda row: row[1], reverse=True) #
    for ip, count in sorted_ips[:10]:  #
        #print(f"- {ip}: {count} krát")
        f.write(f"- {ip} | {count} krat")
        f.write("\n")
            

    #print("-------------------------------------\n")
    f.write("-------------------------------------")    
    f.write("\n")
    f.write("Top 10 IP adries (najmensi):")
    f.write("\n")
    #print(RSip)
    sorted_ips = sorted(RSip.items(), key=lambda row: row[1], reverse=False) #
    for ip, count in sorted_ips[:10]:  # 
        #print(f"- {ip}: {count} krat")
        f.write(f"- {ip} | {count} krat")
        f.write("\n")
    count1=0
    for ip, count in sorted_ips:  # Вывод топ-5 IP
        if count == 1:
            count1= count1+1
    f.write(f'Dalsie ip ktore boly len 1 krat: {count1-10}')
    f.write("\n")    

    #print("-------------------------------------\n")
    f.write("-------------------------------------")
    f.write("\n")
    f.write("Stav:")
    f.write("\n")
    for status, count in RSstatus.items():
        #print(f"- HTTP {status}: {count} krat")
        f.write(f"- HTTP {status} | {count} krat")
        f.write("\n")

    #print("-------------------------------------\n")
    f.write("-------------------------------------")
    f.write("\n")
    f.write("User-Agent:")
    f.write("\n")
    sorted_user_agents = sorted(RSuseragent.items(), key=lambda row: row[1], reverse=True)
    for ua, count in sorted_user_agents[:10]:  # Вывод топ-5 User-Agent
        f.write(f"- {ua} | {count} krat")
        f.write("\n")

    #print("-------------------------------------\n")
    f.write("-------------------------------------")
    f.write("\n")
    f.write("Presmerovania zo stranok:")
    f.write("\n")
    sorted_refer = sorted(RSreferlink.items(), key=lambda row: row[1], reverse=True) #
    for ref, count in sorted_refer[1:11]:  # vypisem top-5 IP
        f.write(f"- {ref} | {count} krat")
        f.write("\n")

    #print("-------------------------------------\n")
    f.write("-------------------------------------")
    f.write("\n")
    f.write("Unikatne IP + URL:") # zoznam jedinečných požiadaviek vo formáte IP + URL, ktoré boli vykonané na server
    f.write("\n")
    i=0
    sortIPURL = sorted(ip_url_counter.items(), key=lambda row: row[1], reverse=True) #
    for ip_url, count in sortIPURL:
        if i<=10: 
            i = i+1
            f.write(f"{ip_url} | {count} ziadosti")
            f.write("\n")
        else:
            pass
    
    #print("-------------------------------------\n")
    f.write("-------------------------------------")
    f.write("\n")
    f.write("Method:")
    f.write("\n")
    for m, count in method_posit.items():
        f.write(f"- {m} | {count} krat")
        f.write("\n")
    
    #print("-------------------------------------\n")
    f.write("-------------------------------------")
    f.write("\n")
    f.write("Stav aj web (404):") #pytame sa otazky ze kolko bolo chyb a kde
    f.write("\n")
    sNrow = sorted(status_with_link.items(), key=lambda row: row[1], reverse=True) #
    i=0
    for m, count in sNrow:
        if i<=5: 
            i = i+1
            f.write(f"- {m} | {count} krat")
            f.write("\n")
        else:
            pass
    
    #print("-------------------------------------\n")
    f.write("-------------------------------------")
    f.write("\n")
    f.write("Stav aj web (505):") #problema na strane servera
    f.write("\n")
    sNrow2 = sorted(status_with_link505.items(), key=lambda row: row[1], reverse=True) #
    i=0
    if not sNrow2:
        f.write("Neexistuje chyb na strane Servera")
        f.write("\n")
    else:
        for m, count in sNrow2:     
            if i<=5: 
                i = i+1
                f.write(f"- {m} | {count} krat")
                f.write("\n")
            else:
                pass

    #print("-------------------------------------\n")
    f.write("-------------------------------------")
    f.write("\n")
    if errorLine !=0:
        f.write(f'Chybny pocet riadkov | {errorLine}')
        f.write("\n")
        f.write(str(errorlog[:1]))
        f.write("\n")
    else:
        pass

    f.close()

#------------------------------------------------------------------------------------------------
def main():

    process = psutil.Process()
    start_time = time.time()
    cpu_start = psutil.cpu_percent(interval=None) #TODO https://www.geeksforgeeks.org/how-to-get-current-cpu-and-ram-usage-in-python/

    file = 'apache_logs.txt'
    allElement, status, ip, useragent, referlink, all_logs, errorLine, errorlog, ip_url, method_posit, status_with_link, status_with_link505 = analyzeFile(file)
    printToFile(allElement, status, ip, useragent, referlink,  errorLine, errorlog, all_logs, ip_url, method_posit, status_with_link, status_with_link505)

    elapsed_time = time.time() - start_time
    peak_memory_usage = process.memory_info().rss / (1024 * 1024) #TODO https://stackoverflow.com/questions/17990227/whats-the-unit-of-rss-in-psutil-process-get-memory-info
    cpu_end = psutil.cpu_percent(interval=None)

    
    cpupercent = (cpu_start + cpu_end) / 2
    print(f"Priemerne vyuzitie CPU: {cpupercent}%")# Средний CPU%
    print(f"Cas vykonania: {elapsed_time:.5f} sec.")
    print(f"Maximalne vyuzitie pamate: {peak_memory_usage:.5f} MB") 

    # tu dávame možnosť vypísať a pozrieť konkrétnu IP podľa vyhľadávania ALEBO vypísať časový interval
    ipS2 = str(input("1 - Analyze podla IP \n2 - Analyza casovych intervalov \n3 - Vyhladavanie podla key?...=... \n4 - Exit \n"))
    if ipS2 == "1": 
        ipS = str(input("Napiste IP kroty potrebujete (IP/0): ")) #priklad "66.169.220.99" 
        if len(ipS)>16:
            print("Error")
        else:
            if ipS == "0":
                print("Správa sa uloží do súboru 'result.txt'")
            else:
                print(f"\nIP: {ipS}")
                for l in all_logs:
                    if l['ip'] == ipS:
                        print(f"-> {l['timestamp']} - {l['request']} {l['status']} {l['size']} {l['user_agent']}")
                print("Správa sa uloží do súboru 'result.txt'")
    elif ipS2 == "2":
        start_time = str(input("Napiste start time - format \"28/Sep/2024:19:06:53 +0200\": "))
        end_time = str(input("Napiste end time - format \"28/Sep/2024:19:06:53 +0200\": "))
        # Priklad volania
        #log_file = 'accesslog.txt'
        # start_time = "28/Sep/2024:19:06:53 +0200"
        # end_time = "28/Sep/2024:19:08:15 +0200"
        timeFile(file, start_time, end_time)
        print("Správa sa uloží do súboru 'result.txt' aj 'resultData.txt'")
        print("-------------------------------================================")
    elif ipS2 == "3":
        keyq = str(input("Napiste kluc ktory chcete vyhladavat - site?.... , napriklad id=5: "))
        keyFile(file, keyq)
        print("Správa sa uloží do súboru 'result.txt' aj 'resultKey.txt'")
        print("-------------------------------================================")
    else:
        print("Exit")
    
main()
