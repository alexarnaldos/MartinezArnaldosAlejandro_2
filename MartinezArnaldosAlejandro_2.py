# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_escanerPuertos
# Purpose:      SpiderFoot plug-in for creating new modules.
#     
# Author:      Alejandro Martinez Arnaldos
# Based on the template: Daniel García Baameiro <dagaba13@gmail.com>
#
# Created:     17/03/2022
# Copyright:   (c) Alejandro Martinez Arnaldos 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import subprocess

class sfp_escanerPuertos(SpiderFootPlugin):

    meta = {
        'name': "Escaner Puertos",
        'summary': "Escaneo con nmap de un nombre de dominio",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive DNS"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["TCP_PORT_OPEN_BANNER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            
            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            ########################
            # Insert here the code #
            ########################
            
            datos = subprocess.run('nmap -F '+eventData,shell=True, text=True, capture_output=True)
            escaneo=datos.stdout

            if not escaneo:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        

        evt = SpiderFootEvent("TCP_PORT_OPEN", escaneo, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_escanerPuertos
