#!/usr/bin/python

#
 #  Copyright (c) 2022 Imtiaz Karim & Abdullah Al Ishtiaq
 #
 #  Licensed under the Apache License, Version 2.0 (the "License");
 #  you may not use this file except in compliance with the License.
 #  You may obtain a copy of the License at
 #
 #      http://www.apache.org/licenses/LICENSE-2.0
 #
 #  Unless required by applicable law or agreed to in writing, software
 #  distributed under the License is distributed on an "AS IS" BASIS,
 #  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #  See the License for the specific language governing permissions and
 #  limitations under the License.
#

# import socket programming library
import socket
import os
import time
import sys
import serial
from stat import *
import logging
import signal
import subprocess
# import thread module
from thread import *
import threading
global device
global environment
print_lock = threading.Lock()
import sys
import platform
from subprocess import Popen
import time
import psutil
# import pyautogui


import os, signal

# GLOBAL VARIABLES
WIN_RUNTIME = ['cmd.exe', '/C']
OS_LINUX_RUNTIME = ['/bin/bash', '-l', '-c']

TASKLIT = 'tasklist'
KILL = ['taskkill', '/F', '/IM']

isWindows = True
environment = ''
DEFAULT_BAUD=115200
DEFAULT_TIMEOUT=1


##################################################################################################
def set_environment():
    global environment, isWindows
    if os.name == 'posix':
        environment = 'linux'
        isWindows = False
    elif os.name == 'nt':
        environment = 'windows'
        isWindows = True
    else:
        raise Exception('EnvironmentError: unknow OS')


# Check if a process is running
def isProcessRunning(serviceName):
    command = ''
    if isWindows:
        command = TASKLIT
    else:
        command = "pidof " + serviceName
        command = OS_LINUX_RUNTIME + [command]

    result = subprocess.check_output(command)
    return serviceName in result


# Used for killing (ADB) process
def killProess(serviceName):
    command = ''
    if isWindows and environment == 'windows':
        command = KILL + [serviceName]
        print command

    elif isWindows == False and environment == 'linux':
        command = "ps -ef | grep " + serviceName + " | grep -v grep | awk '{print $2}' | xargs sudo kill -9"
        command = OS_LINUX_RUNTIME + [command]
    else:
        raise Exception('EnvironmentError: unknow OS')
    subprocess.check_output(command)
    return

def check_pid(pid):        
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def kill(process):
    process_util = psutil.Process(process.pid)
    for child_proc in process_util.children(recursive=True):
        # child_proc.kill()
        os.kill(child_proc.pid, signal.SIGINT)
        outs, errs = child_proc.communicate()
        print("Killed :", child_proc.pid)

    # process.kill()
    os.kill(process.pid, signal.SIGINT)
    outs, errs = process.communicate()
    print("Killed :", process.pid)


###################################################################################################

def function_to_be_executed_concurrently():
    procId = subprocess.Popen('bluetoothctl', stdin = subprocess.PIPE)
    procId.communicate('advertise on')

def kill_process():
     
    # Ask user for the name of process
    name = "bluetoothctl"
    try:
         
        # iterating through each instance of the process
        for line in os.popen("ps ax | grep " + name + " | grep -v grep"):
            fields = line.split()
             
            # extracting Process ID from the output
            pid = fields[0]
             
            # terminating process
            os.kill(int(pid), signal.SIGKILL)
        print("Process Successfully terminated")
         
    except:
        print("Error Encountered while running script")
  

def randomFunction():
    cmd = ['bluetoothctl', 'advertise', 'on']
    #return "import subprocess; procId = subprocess.Popen(['bluetoothctl', 'advertise', 'on', ], stdin = subprocess.PIPE); procId = subprocess.Popen(['bluetoothctl', 'pairable', 'on', ], stdin = subprocess.PIPE);import sys; print(sys.argv[1]);input('Press Enter..')"
    return "import subprocess; procId = subprocess.Popen(['bluetoothctl', 'advertise', 'on', 'pairable', 'on', ], stdin = subprocess.PIPE);import sys; print(sys.argv[1]);input('Press Enter..')"

processes = None

btstack_process = None

def handle_reset(client_socket):

    print '--- START: Handling RESET command ---'
    if device in ["nexus6"]:
        print "initial sleep"
        print "turning off..."
        time.sleep(1)
        os.system("adb shell am start -a android.settings.BLUETOOTH_SETTINGS")
        time.sleep(2)
        os.system("adb shell input tap 1326 406")
        time.sleep(2)
        os.system("adb shell input tap 1326 406")
        time.sleep(2)
        os.system("adb shell input tap 337 2488")
        time.sleep(10)
        os.system("adb shell input tap 1260 396")
        time.sleep(1)
        os.system("adb shell input tap 1348 383")
        time.sleep(1)
        os.system("adb shell input tap 1330 600")
        time.sleep(1)
        print "turned on"
        client_socket.send('DONE\n')

    
    print '### DONE: Handling RESET command ###'

def handle_accept_pair(client_socket, ack_required):
    if device in ["nexus6"]:
        print("got accept pair in nexus6")
        time.sleep(2)
        os.system("adb shell input tap 1236 1477")    # turn device bluetooth on
        time.sleep(1)
    if(ack_required):
        client_socket.send('DONE\n')
        print '### DONE: Handling accept pair command ###'


def handle_accept_pair_confirm(client_socket, ack_required):
    if device in ["nexus6"]:
        os.system("adb shell input tap 640 2240") 
        os.system("adb shell input tap 640 2240") 
        os.system("adb shell input tap 640 2240") 
        os.system("adb shell input tap 640 2240") 
        os.system("adb shell input tap 640 2240") 
        os.system("adb shell input tap 640 2240") 
        os.system("adb shell input tap 1225 1279")  
    if(ack_required):
        client_socket.send('DONE\n')
        print '### DONE: Handling handle_accept_pair_confirm command ###'


def handle_dh_key_confirm(client_socket, ack_required):
    if device in ["nexus6"]:
        os.system("adb shell input tap 1116 1565") 
    if(ack_required):
        client_socket.send('DONE\n')
        print '### DONE: Handling handle_dh_key_confirm command ###'




####################################################################################################
# thread fuction
def client_handler(client_socket):

    while True:


        data = client_socket.recv(1024)

        if not data:
            print('Bye')
            # lock released on exit
            print_lock.release()
            break

        command = data.lower().strip()

        print "GOT COMMAND : " + command

        if "reset" in command:
            handle_reset(client_socket)

        if "accept_pair" in command:
            handle_accept_pair(client_socket, True)

        if "accept_pair_confirm" in command:
            handle_accept_pair_confirm(client_socket, True)
        
        if "dh_key_confirm" in command:
            handle_dh_key_confirm(client_socket, True)

    client_socket.close()

def Main():
    global environment
    global device
    host = ""
    # if (len(sys.argv)<2):
    #     print 'Usage: TCPServer-new.py <hostname> l,w'
    #     exit()

    if (len(sys.argv)<3):
        print 'Usage: TCPServer-new.py <hostname> l,w <device name> nexus6'
        exit()

    if sys.argv[1] is "l":
        environment = "linux"
    else:
        environment = "windows"

    device = sys.argv[2] 
    
    print str(sys.argv)

    print '#############################################'
    print '######### BLE Controller started #############'
    print '#############################################'

    print 'Initializing the controller...'
    port = 61000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print("socket binded to post", port)

    # put the socket into listening mode
    s.listen(5)
    print("socket is listening")

    while True:
        # establish connection with client
        client_socket, addr = s.accept()

        # lock acquired by client
        print_lock.acquire()
        print('Connected to :', addr[0], ':', addr[1])

        # Start a new thread and return its identifier
        start_new_thread(client_handler, (client_socket,))
    s.close()


if __name__ == '__main__':
    Main()