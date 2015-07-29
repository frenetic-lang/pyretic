'''
Created on Jul 10, 2012

@author: Peyman Kazemian
'''
from abc import ABCMeta,abstractproperty,abstractmethod

class hs_hash_table:
    '''
    The base class for all hash tables
    '''
    __metaclass__ = ABCMeta
    
    @abstractproperty
    def length(self):
        pass
    
    @abstractmethod
    def add_entry(self,wildcard_match,ports,obj):
        '''
        @wildcard_match: the match structure of type wildcard
        @ports: list of matching ports for this entry
        @obj: object to be returned when matching.
        '''
        pass
    
    @abstractmethod
    def del_entry(self,wildcard_match,ports,obj):
        '''
        @wildcard_match: the match structure of type wildcard
        @ports: list of matching ports for this entry
        @obj: object to be returned when matching.
        '''
        pass
    
    def find_entries(self,wildcard_search,port):
        '''
        @wildcard_match: the match structure to searc for
        @port: the input port to match on
        @return: a list of matching entry objects, or None if everything matches.
        '''
        pass