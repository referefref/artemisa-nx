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

SCRIPTS_DIR = "./scripts/"
ON_FLOOD_SCRIPT_PATH = SCRIPTS_DIR + "on_flood.sh"
ON_SPIT_SCRIPT_PATH = SCRIPTS_DIR + "on_spit.sh"
ON_SCANNING_SCRIPT_PATH = SCRIPTS_DIR + "on_scanning.sh"

import os
from subprocess import Popen, PIPE, STDOUT

from modules.logger import logger

def RunActionScript(Script, Template, Results):
    """
    artemisa-nx: runs an action script with the parameters defined in actions.conf. The template
    is split into words first and the variables are replaced inside each word, so every word
    becomes exactly one argument and nothing taken from the SIP message reaches a shell.
    """
    Values = {"$From_Extension$": Results.From_Extension,
              "$From_IP$": Results.From_IP,
              "$From_Port$": Results.From_Port,
              "$From_Transport$": Results.From_Transport,
              "$Contact_IP$": Results.Contact_IP,
              "$Contact_Port$": Results.Contact_Port,
              "$Contact_Transport$": Results.Contact_Transport,
              "$Connection_IP$": Results.Connection,
              "$Owner_IP$": Results.Owner,
              "$Tool_name$": Results.ToolName}
    try:
        Values["$Via_IP$"] = Results.Via[0][0]
        Values["$Via_Port$"] = Results.Via[0][1]
    except:
        pass

    Args = []
    for Word in Template.split():
        for Key in Values:
            Word = Word.replace(Key, Values[Key])
        Args.append(Word)

    Command = ["bash", Script] + Args
    logger.info("Executing " + " ".join(Command) + " ...")
    try:
        Process = Popen(Command, stdout=PIPE, stderr=STDOUT, universal_newlines=True, errors="replace")
        for line in Process.communicate()[0].splitlines():
            if line.strip() != "":
                logger.info(line.strip())
    except Exception as e:
        logger.error("Cannot execute script. Details: " + str(e))

def Correlator(Results, Flood, On_flood_parameters, On_SPIT_parameters, On_scanning_parameters):
    """
    Keyword Arguments:
    Results -- an instance of commons.CallData
    Flood -- flag from core.py

    """
    
    prtString = "************************************** Correlation ***************************************"; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
    prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
    prtString = "Artemisa concludes that the arrived message is likely to be:"; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
    prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

    ####################################################################################
    ####################################################################################
    ##                                                                                ##
    ## TODO: For now, this is a very simple correlator that should be improved.       ##
    ##                                                                                ##
    ## The "Results" parameter is a CallData object which contains all the data       ##    
    ## related with the call and the classifier, so if you wish you can extract it    ##
    ## and define your own rules.                                                     ##
    ##                                                                                ##
    ####################################################################################
    ####################################################################################
    
    if IfCategory("Attack tool", Results.Classification):
        prtString = "* The attack was created employing the tool " + Results.ToolName + "."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    if CheckIfFlood(Results, Flood, On_flood_parameters):
        return

    if CheckIfSPIT(Results, On_SPIT_parameters):
        return
     
    CheckIfScanning(Results, On_scanning_parameters)

    if IfCategory("Ringing", Results.Classification):
        prtString = "* The message belongs to a ringing attack."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
def CheckIfFlood(Results, Flood, On_flood_parameters):
    """
    Keyword Arguments:
    Results -- A CallData instance that contains call information.

    This functions runs a script if flood was detected.
    """
    if Flood:
        prtString = "* A flooding attack."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        RunActionScript(ON_FLOOD_SCRIPT_PATH, On_flood_parameters, Results)

    return Flood

def CheckIfSPIT(Results, On_SPIT_parameters):
    """
    Keyword Arguments:
    Results -- A CallData instance that contains call information.

    This functions runs a script if certain data was found on the call.
    """
    if IfCategory("SPIT",Results.Classification):
    
        prtString = "* A SPIT call."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        RunActionScript(ON_SPIT_SCRIPT_PATH, On_SPIT_parameters, Results)
        
        return True

    return False

def CheckIfScanning(Results, On_scanning_parameters):
    """
    Keyword Arguments:
    Results -- A CallData instance that contains call information.

    This functions runs a script if certain data was found on the call.
    """
    if IfCategory("Scanning",Results.Classification):

        prtString = "* A scanning attempt."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
    
        RunActionScript(ON_SCANNING_SCRIPT_PATH, On_scanning_parameters, Results)

        return True

    return False

def IfCategory(Category, Classification):
    """
    Returns whether a category is found or not.
    """
    Found = False
       
    for i in range(len(Classification)):
        if Classification[i] == Category:
            Found = True
            break

    if Found: 
        return True
    else:
        return False
