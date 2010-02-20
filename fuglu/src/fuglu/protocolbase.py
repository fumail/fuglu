#   Copyright 2009 Oli Schacher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Id: core.py 81 2010-02-17 08:43:33Z gryphius $
#

class ProtocolHandler(object):
    def __init__(self,socket,config):
        self.socket=socket
        self.config=config
        
    
    def get_suspect(self):
        return None
        
        
    def commitback(self,suspect):
        pass
    
    def defer(self,reason):
        pass
    
    def discard(self,reason):
        pass
    
    def reject(self,reason):
        pass