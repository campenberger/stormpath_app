import logging
import json
import threading
from collections import namedtuple


def loggingFactory(module):
    ''' Factory method that returns a logger generation function with the
        prefix for the modules where it is used.

            _getLogger=loggingFactory('util.alstore')
            logger=_getLogger('method')
            logger.debug('Bla')
            >>> adr.util.alstore.method DEBUG Bla
    '''

    def getLogger(method=None):
        name=module if method is None else module+"."+method
        return logging.getLogger('authserver.'+name)

    return getLogger

_getLogger=loggingFactory('util')

class Storage(dict):
    """
    Shamelessly stolen from web.py
    
    A Storage object is like a dictionary except `obj.foo` can be used
    in addition to `obj['foo']`.
    
        >>> o = storage(a=1)
        >>> o.a
        1
        >>> o['a']
        1
        >>> o.a = 2
        >>> o['a']
        2
        >>> del o.a
        >>> o.a
        Traceback (most recent call last):
            ...
        AttributeError: 'a'
    
    """
    def __getattr__(self, key): 
        try:
            return self[key]
        except KeyError, k:
            raise AttributeError, k
    
    def __setattr__(self, key, value): 
        self[key] = value
    
    def __delattr__(self, key):
        try:
            del self[key]
        except KeyError, k:
            raise AttributeError, k
    
    def __repr__(self):     
        return json.dumps(self)



class LockManager(object):
    ''' Context manager class for rerentrant thread locks

        <pre><code>
        lm=LockManager('MyLock)
        with lm:
            # protected code block
        </code></pre>
    '''

    def __init__(self,name):
        ''' Constructor with name of Thread lock '''
        self.name=name
        self.lock=threading.RLock()
   
    def __enter__(self):
        logger=_getLogger('LockManager')
        logger.debug('Acquiring lock {}...'.format(self.name))

        self.lock.acquire()

        logger.debug('Lock {} acquired'.format(self.name))


    def __exit__(self,exc_type,exc_value,traceback):
        self.lock.release()
        _getLogger('LockManager').debug('Log {} released'.format(self.name))
        return None


_SingletonDef=namedtuple("_SingletonDef",["name","class_obj","args","kwargs"])
class Singletons(object):

    def __init__(self):
        self._constuctorMap={}
        self._singletons={}

    def register_singleton(self,name,class_obj,args,kwargs):
        self._constuctorMap[name]=_SingletonDef(name,class_obj,args,kwargs)

    def get(self,name):
        if name not in self._singletons:
            if name in self._constuctorMap:
                defintion=self._constuctorMap[name]
                self._singletons[name]=defintion.class_obj(*defintion.args,**defintion.kwargs)
            else:
                raise ValueError("Unknown singleton {} requested".format(name))
        return self._singletons[name]

_singletons=Singletons()

def register_singleton(name,class_obj,*args,**kwargs):
    global _singletons
    _singletons.register_singleton(name,class_obj,args,kwargs)

def get_singleton(name):
    global _singletons
    return _singletons.get(name)
