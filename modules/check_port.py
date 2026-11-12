# -*- coding: UTF-8 -*-

# This is part of Artemisa.
# 
# Artemisa is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# Artemisa is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with Artemisa. If not, see <http://www.gnu.org/licenses/>.

import sys

# Set a path to the main root
sys.path.append("../")

from subprocess import Popen
from subprocess import PIPE
from libs.IPy.IPy import *       # Module to deal with IPs

from modules.logger import logger
from modules.commons import IsSafeArgument

def CheckPort(strIP, Port, Transport, verbose):
    """
    This function checks a given IP:port and it's used for both SIP and media ports analysis    
    """    
    if strIP == "" or Port == "": return -1

    # artemisa-nx: values come from the SIP message, so they are checked and passed to nmap
    # as separate arguments instead of through a shell.
    if not IsSafeArgument(strIP) or not Port.isdigit():
        logger.warning("Not scanning " + repr(strIP) + ":" + repr(Port) + " (not a plain host and port).")
        return -1
    
    DataToSend = ""
    
    try:        
        if Transport == "udp":
            Args = ["nmap", "-sU", strIP, "-p", Port]
            Command = " ".join(Args)
            Process = Popen(Args, stdout=PIPE, universal_newlines=True)

        elif Transport == "tcp":
            Args = ["nmap", "-sS", strIP, "-p", Port]
            Command = " ".join(Args)
            Process = Popen(Args, stdout=PIPE, universal_newlines=True)

        else:
            return -1
            
        if verbose:
            DataToSend = "+ Verbose" + "\n"
            DataToSend = DataToSend + "| Tool employed: " + Command + "\n"
            DataToSend = DataToSend + "|" + "\n"
                        
        Process.wait()
        
        strData = Process.communicate()[0].strip().split("\n")
        
        if verbose:
            DataToSend = DataToSend + "| Tool output:" + "\n"
            for line in strData:
                DataToSend = DataToSend + "| " + line + "\n"
            DataToSend = DataToSend + "\n"
                
        strState = ""
        
        # FIXME: The following lines parse the output returned by nmap. This part can be modified
        # in order to do a better parsing such as parsing the XML file. This will be for the future.
        for line in strData:
            if line.find(Port + "/" + Transport) != -1:
                strState = line.split(" ")[1]
                break
                
        if strState != "":
            return DataToSend + "Port state: " + strState
        else:
            return -1
            
                
    except OSError:
        logger.warning("nmap is not installed.")
        return -1

        
    
    
if __name__ == '__main__':
    if len(sys.argv) == 5:
        print(CheckPort(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]))
    else:
        print("Arguments are required!")
        sys.exit(1)
