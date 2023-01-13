#conding = utf-8
import os
import re
import argparse
import threading
import datetime
import xml.dom.minidom
from progressbar import *
from lib.color import output
from lib.console import console_width
from lib.crawler import *
from lib.config import constant
from hackScanner.pdf import *
import signal
scandone=False
#global
lock = threading.Lock()
progress = ProgressBar()
now = datetime.datetime.now()

logs = {"path":[],"line":[],"type":[]} 
files = []  #文件集
file_scanned_count = 0
target = ''
def maininit():
    global target,file_scanned_count,files,logs,scandone
    target=''
    file_scanned_count=0
    files=[]
    logs = {"path": [], "line": [], "type": []}
    scandone = False

def get_ext_type(path):
    allow_ext = ['php','js','html','jsp','py','asp','java']

    basename = os.path.basename(os.path.abspath(path))
    ext = basename[basename.rfind('.')+1:]

    if ext in allow_ext:
        return ext
    else:
        return False

def scandir(path):     #扫描给定目录，获取文件集（以绝对路径返回）
    basedir = os.path.abspath(path)
    dirs = os.listdir(basedir)
    dirs = [os.path.join(basedir,dir) for dir in dirs]
    
    for dir in dirs:
        if os.path.isdir(dir):
            scandir(dir)
        else:
            files.append(dir)
    progress.start(len(files))

def multi_scan(threads):
    file_blocks = []
    size = len(files) // threads

    for i in range(threads-1):
        file_blocks.append(files[i*size:i*size+size])
    file_blocks.append(files[(threads-1)*size:])
    
    t=threading.Thread(target=start_progress)
    t.start()

    for j in range(threads):
        files_to_scan = file_blocks[j]
        threading.Thread(target=scan,args=(files_to_scan,)).start()
    t.join()

def start_progress():   #监测扫描进度
    content=""
    while True:
        lock.acquire()
        progress.update(file_scanned_count)
        if file_scanned_count == len(files):  #扫描完成
            f = open('result/'+str(now.year)+str(now.month)+str(now.day)+"_"+target,'w',encoding='utf8')
            f2 = open('result/scanlog.txt','w',encoding='utf8')
            f3 = open('result/scanlog.md','w',encoding='utf8')
            f3.write("# web扫描结果\n")
            f3.write("```shell\n")

            for i in range(len(logs['path'])):
                f.write("line:"+logs['line'][i]+"\t"+logs['path'][i]+"\t"+"type:"+logs['type'][i]+"\n")
                f2.write("【line:"+logs['line'][i]+"】 "+logs['path'][i]+"\t"+"type:"+logs['type'][i]+"\n")
                f3.write("【line:"+logs['line'][i]+"】 "+logs['path'][i]+"\t"+"type:"+logs['type'][i]+"\n")
                content=content+"【line:"+logs['line'][i]+"】 "+logs['path'][i]+" "+"type:"+logs['type'][i]+"<br/>"
            lock.release()
            output.warning("\n扫描完成，共有"+str(len(logs['path']))+"处代码可能存在高危漏洞")
            f2.write("\n扫描完成，共有"+str(len(logs['path']))+"处代码可能存在高危漏洞")
            f3.write("\n扫描完成，共有"+str(len(logs['path']))+"处代码可能存在高危漏洞\n")
            content=content+"扫描完成，共有"+str(len(logs['path']))+"处代码可能存在高危漏洞"
            story.append(Paragraph("漏洞检测报告", Title))
            story.append(Paragraph(content, body))
            doc = SimpleDocTemplate('result/scanlog.pdf')
            doc.build(story)
            f3.write("```")
            progress.update(len(files))

            break
        lock.release()

def scan(files_to_scan):
    global file_scanned_count
    for file in files_to_scan:
        type = get_ext_type(file)
        if type:    #排除掉一些二进制文件
            patterns = parse_xml_for_type(type)
            with open(file,'r',encoding='utf-8') as f:
                scan_line_num = 0
                for line in f:
                    scan_line_num += 1
                    line = line.strip('\n')
                    result = match(line,patterns)   #匹配内容
                    if result:
                        lock.acquire()
                        msg = "[-]line:{}    {}    type:{}".format(str(scan_line_num),file,result)
                        output.error('\r'+msg+' '*(console_width-len(msg)))
                        logs['path'].append(file)
                        logs['line'].append(str(scan_line_num))
                        logs['type'].append(result)
                        lock.release()
        lock.acquire()
        file_scanned_count += 1
        lock.release()

def match(content,patterns):
    for type,pattern in patterns.items():
        p = re.compile(r'{}'.format(pattern),re.I)
        if p.search(content):
            return type

def parse_xml_for_type(language_type):
    lock.acquire()
    DOMTree = xml.dom.minidom.parse(constant.parse_xml)
    lock.release()
    collection = DOMTree.documentElement

    result = {}
    types = collection.getElementsByTagName(language_type)
    for language_type in types:
        patterns = language_type.getElementsByTagName('pattern')
        for pattern in patterns:
            code = pattern.getElementsByTagName('code')[0].childNodes[0].data
            type = pattern.getElementsByTagName('type')[0].childNodes[0].data
            result[type] = code
    return result
    
def mainstartScanner(target,threads):
    if threads > constant.thread_max:
        threads = constant.thread_max
    scandir(target)
    multi_scan(threads)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='web code scanner client. ')
    parser.add_argument('-t','--type',help='choose the scanner or the crawler,use "-t scanner" for scanner,use "-t crawler" for crawler')

    args = parser.parse_args()
    args.type='scanner'
    if args.type == 'scanner':
        output.info("[?]请输入需要扫描的项目路径：",end='')
        target = input()
        output.info("[?]请输入扫描线程数（max="+str(constant.thread_max)+"):",end='')
        threads = int(input())
        if threads > constant.thread_max:
            threads = constant.thread_max
        scandir(target)
        multi_scan(threads)
    elif args.type == 'crawler':
        output.info("[?]如果想下载网页内容，请输入对应网址,否则输入None")
        url_temp=input()
        if url_temp!="None":
            url=url_temp
        main(url)