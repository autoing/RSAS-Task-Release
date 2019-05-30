import os
import re
import time
import favicon
import requests
from main.UserInterface import *
from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import QTimer, QThread, pyqtSignal
requests.packages.urllib3.disable_warnings()

class LoginWindow(QtWidgets.QMainWindow, Login):
    def __init__(self, parent=None):
        super(LoginWindow, self).__init__(parent)
        self.setupUi(self)
        self.setWindowTitle("登陆")
        #设置图标
        self.setWindowIcon(QtGui.QIcon(':/favicon.ico'))
        #获取显示器的分辨率
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        #获取程序的宽和高
        size = self.geometry()
        #实现在屏幕中间显示程序
        self.move((screen.width() - size.width())/2, (screen.height() - size.height())/2)
        # 配置文件，有就算了，没有就写一个
        setini = """[扫描器地址]
host = 127.0.0.1
port = 443
survival_port = 21,22,23,25,80,443,445,139,3389,6000

[任务配置]
系统名称|2011-1-1 11:11:11"""
        # 从配置文件取出扫描器的IP
        try:
            with open('set.ini') as content:
                self.localhost = content.readlines()[1:3]
                self.host = self.localhost[0].split('=')[1].strip()
                self.port = self.localhost[1].split('=')[1].strip()
            global server
            if self.port == '443':
                server = 'https://{}'.format(self.host)
            else:
                server = 'https://{}:{}'.format(self.host,self.port)
        except Exception as e:
            with open('set.ini','a',encoding='gb18030') as set_ini:
                set_ini.write(setini)
            QtWidgets.QMessageBox.information(None, "提示！", "请修改同目录下的配置文件，重新打开软件！", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No ,  QtWidgets.QMessageBox.Yes )
            exit()

        # 创建资产文件夹
        try:
            os.mkdir('Assets')
        except Exception as e:
            pass
        self.login_Button.clicked.connect(self.login)

    def login(self):
        # 从输入框获取用户名、密码
        self.username = self.username_lineEdit.text().strip()
        self.passwd = self.passwd_lineEdit.text().strip()
        self.login_url = '{}/accounts/'.format(server)
        # 登陆扫描器，成功跳转到主界面
        try:
            global cookies
            # 获取扫描器未登录状态的CSRF值
            self.csrftoken = self.get_login(self.login_url)
            # 登陆扫描器
            cooker = self.post_login(self.login_url,self.csrftoken,self.username,self.passwd)
            # 获取登陆扫描器成功后的cookie
            cookies = requests.utils.dict_from_cookiejar(cooker.cookies)
            # 到这里就是登陆成功了，关闭登录界面，打开主界面
            self.close()
            self.admin_window = AdminWindow()
            self.admin_window.show()
        except Exception as e:
            QtWidgets.QMessageBox.information(None, "提示！", "密码错误！", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No ,  QtWidgets.QMessageBox.Yes )


    
    # 正则：获取扫描器未登录状态的CSRF值
    def get_token(self,content):
        return re.findall("""<input type='hidden' name='csrfmiddlewaretoken' value="(.*)">""",content)[0]

    # 获取扫描器未登录状态的CSRF值
    def get_login(self,login_url):
        content = requests.get(self.login_url,verify=False, allow_redirects=False,timeout=3)
        return self.get_token(content.text)

    # 登陆扫描器
    def post_login(self,login_url,csrftoken,username,passwd):
        headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36",
        "Referer": self.login_url,
        "Cookie": "csrftoken={}".format(self.csrftoken)
        }
        postdata = {
        'username': self.username,
        'password': self.passwd,
        'csrfmiddlewaretoken': self.csrftoken
        }
        return requests.post(self.login_url + 'login_view/', headers=headers, data=postdata, verify=False, allow_redirects=False,timeout=3)


class AdminWindow(QtWidgets.QMainWindow,Admin):
    def __init__(self, parent=None):
        super(AdminWindow, self).__init__(parent)
        self.setupUi(self)

        self.setWindowTitle("RSAS 批量下达任务1.0")
        #设置图标
        self.setWindowIcon(QtGui.QIcon(':/favicon.ico'))
        #获取显示器的分辨率
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        #获取程序的宽和高
        size = self.geometry()
        #实现在屏幕中间显示程序
        self.move((screen.width() - size.width())/2, (screen.height() - size.height())/2)

        # 扫描器的扫描模板
        self.template = {'0':'自动匹配扫描'}
        # 扫描器的任务状态，没什么用的，使用线程，避免卡界面
        self.Status = Status(server,cookies['csrftoken'],cookies['sessionid'])
        self.Status.log_return.connect(self.status_finish)
        self.Status.start()
        #这里获取扫描器的扫描模板，保存为软件的下拉框
        self.start_Button.clicked.connect(self.admin)
        self.scanning_template(server,cookies['csrftoken'],cookies['sessionid'])

    def scanning_template(self,server,csrftoken,sessionid):
        content_re = """<tr class=".*?">.*?<th>漏洞模板</th>.*?<td>.*?<select id='.*?'.*?style=".*?">(.*?)</select>.*?</td>.*?</tr>"""
        template_re = """<option value='(\d+)' >(.*?)</option>"""
        headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36",
        "Cookie": "csrftoken={}; sessionid={}".format(csrftoken,sessionid)
        }
        headers['Referer'] = server
        content = requests.get(server+'/task/',headers=headers,verify=False, allow_redirects=False)
        cont = re.findall(content_re,content.text,re.S|re.M)
        # 把扫描器的扫描模板生成下拉框
        self.template.update(dict(re.findall(template_re,cont[0],re.S|re.M)))
        self.TemplateList_comboBox.addItems(self.template.values())
        self.TemplateList_comboBox.setCurrentIndex(0)

    def admin(self):
        # 获取当前下拉框的字符
        scan_mode = self.TemplateList_comboBox.currentText()
        # 通过字符找到模板对应的数字，就是字典，通过值取键。扫描器的扫描模板对应不同的数字，扫描器在下任务时依照该数字选择对应的模板
        tpl = list(self.template.keys())[list(self.template.values()).index (scan_mode)]
        # 这里就是主界面的四个按钮勾选状态了
        SetPost_status = self.AllPort_checkBox.isChecked()
        DefaultPort_status = self.DefaultPort_checkBox.isChecked()
        survival_cancel_status = self.survival_cancel_checkBox.isChecked()
        survival_Definition_status = self.survival_Definition_checkBox.isChecked()
        # 这里就是下任务了，使用线程，避免卡界面
        self.start_Button.setChecked(True)
        self.start_Button.setDisabled(True)
        self.Start = Working(server,cookies['csrftoken'],cookies['sessionid'],tpl,SetPost_status,DefaultPort_status,survival_cancel_status,survival_Definition_status)
        self.Start.start_return.connect(self.start_finish)
        self.Start.start()

    # 这个是主界面修改显示用的
    def start_finish(self, start_msg):
        self.Working_label.setText(start_msg)
        if '所有任务下达完成' in start_msg:
            self.start_Button.setChecked(False)
            self.start_Button.setDisabled(False)

    # 这个是主界面修改显示用的
    def status_finish(self, status_msg):
        global number
        number = status_msg.split('|')
        self.Status_label.setText("状态：当前有{}个任务正在进行,{}个任务等待扫描".format(number[0],number[1]))
        

class Working(QThread):
    
    start_return = pyqtSignal(str)
    
    def __init__(self,server,csrftoken,sessionid,tpl,SetPost_status,DefaultPort_status,survival_cancel_status,survival_Definition_status):
        super(Working, self).__init__()
        self.server = server
        self.csrftoken = csrftoken
        self.sessionid = sessionid
        self.tpl = tpl
        self.SetPost_status = SetPost_status
        self.DefaultPort_status = DefaultPort_status
        self.survival_cancel_status = survival_cancel_status
        self.survival_Definition_status = survival_Definition_status


    def run(self):
        # 扫描器下的任务要很多的参数，下边都是POST请求要发送的准备数据
        if self.SetPost_status == True:
            port_strategy = 'user'
            port_strategy_userports = '1-65535'
        if self.DefaultPort_status == True:
            port_strategy = 'standard'
            port_strategy_userports = '1-100,443,445'
        if self.survival_Definition_status == True:
            with open('set.ini') as cent:
                live_tcp_ports = cent.readlines()[3:4][0].split('=')[1].strip()
        else:
            live_tcp_ports = '21,22,23,25,80,443,445,139,3389,6000'

        with open('set.ini') as content:
            task_list = content.readlines()[6:]
        i = 1
        for _task in task_list:
            self.start_return.emit('共{}个任务，正在下达第{}个任务...'.format(len(task_list),i))
            task_info = _task.split('|')
            try:
                task_name = task_info[0].strip()
                task_time = task_info[1].strip()
                task_start_time = 'timing'
            except Exception as e:
                task_name = _task.strip()
                task_time = number[2]
                task_start_time = 'immediate'

            iplist = ''
            loginarray = []
            try:
                with open('./Assets/'+task_name+'.txt') as cent:
                    for ip in cent:
                        loginarray.append({"ip_range": "{}".format(ip.strip()), "admin_id": "", "protocol": "", "port": "", "os": "", "user_name": "", "user_pwd": "", "ostpls": [], "apptpls": [], "dbtpls": [], "virttpls": [], "devtpls": [], "statustpls": "", "tpl_industry": "", "tpllist": [], "tpllistlen": 0, "jhosts": [], "tpltype": "", "protect": "", "protect_level": "", "jump_ifuse": "", "host_ifsave": "", "oracle_ifuse": "", "ora_username": "", "ora_userpwd": "", "ora_port": "", "ora_usersid": "", "weblogic_ifuse": "", "weblogic_system": "", "weblogic_version": "", "weblogic_user": "", "weblogic_path": ""})
                        iplist += ';'+ip.strip()
            except Exception as e:
                self.start_return.emit('警告！找不到相关资产，请检查！'.format(len(task_list),i))
                with open('log.txt','a') as content:
                    content.write('找不到资产：{}\n'.format(task_name))
                time.sleep(1)
                break

            data = {
            "csrfmiddlewaretoken": self.csrftoken,
            "vul_or_pwd": "vul",
            "config_task": "taskname",
            "task_config": "",
            "diff": "write something",
            "target": "ip",
            "ipList": iplist[1:],
            "domainList": "",
            "name": task_name,
            "exec": task_start_time,
            "exec_timing_date": task_time,
            "exec_everyday_time": "00:00",
            "exec_everyweek_day": "1",
            "exec_everyweek_time": "00:00",
            "exec_emonthdate_day": "1",
            "exec_emonthdate_time": "00:00",
            "exec_emonthweek_pre": "1",
            "exec_emonthweek_day": "1",
            "exec_emonthweek_time": "00:00",
            "tpl": self.tpl,
            "login_check_type": "login_check_type_vul",
            "exec_range": "",
            "scan_pri": "2",
            "taskdesc": "",
            "report_type_html": "html",
            "report_content_sum": "sum",
            "report_content_host": "host",
            "report_tpl_sum": "1",
            "report_tpl_host": "101",
            "report_ifsent_type": "html",
            "report_ifsent_email": "",
            "port_strategy": port_strategy,
            "port_strategy_userports": port_strategy_userports,
            "port_speed": "3",
            "port_tcp": "T",
            "live": "on",
            "live_icmp": "on",
            "live_tcp": "on",
            "live_tcp_ports": live_tcp_ports,
            "scan_level": "3",
            "timeout_plugins": "40",
            "timeout_read": "5",
            "alert_msg": "远程安全评估系统将对您的主机进行安全评估。",
            "scan_oracle": "yes",
            "encoding": "GBK",
            "bvs_task": "no",
            "pwd_smb": "yes",
            "pwd_type_smb": "c",
            "pwd_user_smb": "smb_user.default",
            "pwd_pass_smb": "smb_pass.default",
            "pwd_telnet": "yes",
            "pwd_type_telnet": "c",
            "pwd_user_telnet": "telnet_user.default",
            "pwd_pass_telnet": "telnet_pass.default",
            "pwd_ssh": "yes",
            "pwd_type_ssh": "c",
            "pwd_user_ssh": "ssh_user.default",
            "pwd_pass_ssh": "ssh_pass.default",
            "pwd_timeout": "5",
            "pwd_timeout_time": "120",
            "pwd_interval": "0",
            "pwd_num": "0",
            "pwd_threadnum": "5",
            "loginarray": loginarray
            }

            if self.survival_cancel_status == True:
                data.pop('live')
                data.pop('live_icmp')
                data.pop('live_tcp')
                data.pop('live_tcp_ports')

            headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36",
            "Cookie": "csrftoken={}; sessionid={}".format(self.csrftoken,self.sessionid)
            }
            headers['Referer'] = self.server+'/task/'
            # 到了这里才是下任务的请求包
            content = requests.post(self.server + '/task/vul/tasksubmit', headers=headers, data=data, verify=False, allow_redirects=False)
            if 'Errors' in content.text:
                self.start_return.emit('第{}个任务存在重复IP，下达任务失败...'.format(i))
                with open('log.txt','a') as content:
                    content.write('重复IP：{}\n'.format(task_name))
                time.sleep(1)
            else:
                self.start_return.emit('共{}个任务，任务 {} 创建成功...'.format(len(task_list),content.text.split(':')[2]))
            i += 1
            time.sleep(1)
        self.start_return.emit('共{}个任务，所有任务下达完成...'.format(len(task_list)))

class Status(QThread):
    
    log_return = pyqtSignal(str)
    
    def __init__(self,server,csrftoken,sessionid):
        super(Status, self).__init__()
        self.server = server
        self.csrftoken = csrftoken
        self.sessionid = sessionid

    def run(self):
        # 获取任务的数量
        task_re = """<input type='hidden' value='(.*?)' id = 'taskids' />"""
        # 获取扫描器的时间，写到后边发现这一步多余了
        time_re = """<span id ="sys_time">(.*?)</span>"""
        headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36",
        "Cookie": "csrftoken={}; sessionid={}".format(self.csrftoken,self.sessionid)
        }
        headers['Referer'] = self.server
        while True:
            # 获取任务的数量
            now_list = requests.get(self.server+'/list/getScaning/status/3',headers=headers,verify=False, allow_redirects=False)
            list_id = re.findall(task_re,now_list.text)[0]
            nowtask_id = []
            for _id in list_id.split(';'):
                if _id:
                    nowtask_id.append(_id)
            # 获取等待扫描任务的数量
            wait_list = requests.get(self.server+'/list/getScaning/status/12',headers=headers,verify=False, allow_redirects=False)
            list_id = re.findall(task_re,wait_list.text)[0]
            waittask_id = []
            for _id in list_id.split(';'):
                if _id:
                    waittask_id.append(_id)
            # 获取扫描器的时间，写到后边发现这一步多余了
            content = requests.get(self.server,headers=headers,verify=False, allow_redirects=False)
            server_time = re.findall(time_re,content.text,re.S|re.M)[0].split(' ')
            servertime = '{} {}:{}:00'.format(server_time[1],server_time[0].split(':')[0],int(server_time[0].split(':')[1])+2)
            self.log_return.emit('{}|{}|{}'.format(len(nowtask_id),len(waittask_id),servertime))
            time.sleep(1)
