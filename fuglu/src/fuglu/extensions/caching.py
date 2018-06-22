import functools
import time
import operator

def smart_cached_property(inputs=[]):
    # from -> http://code.activestate.com/recipes/576563-cached-property/?in=user-4167995#c4
    def smart_cp(f):
        @functools.wraps(f)
        def get(self):
            input_values = dict((key,getattr(self,key)) for key in inputs )

            #  cstats: stats for cached hits
            # ucstats: stats for uncached hits
            cstats,ucstats = get_statscounter(self)

            # get dict with caching limits
            climits = get_cachinglimits(self,f.func_name)

            try:
                x = self._property_cache[f]
                if not climits.get('nocache'):
                    if input_values == self._property_input_cache[f]:
                        stats_increment(cstats,f)
                        return x
            except AttributeError:
                self._property_cache ={}
                self._property_input_cache = {}
            except KeyError:
                pass

            x = self._property_cache[f] = f(self)
            self._property_input_cache[f] = input_values

            stats_increment(ucstats,f)

            return x
        return property(get)
    return smart_cp

def smart_cached_memberfunc(inputs=[]):
    def smart_cm(f):
        @functools.wraps(f)
        def get(self,*args,**kwargs):
            input_values = dict((key,getattr(self,key)) for key in inputs )
            # need immutable object because fun_input will be used as the key
            # in the dict and therefore has to be hashable
            fun_input = args + tuple([item for item in kwargs.items()])

            #  cstats: stats for cached hits
            # ucstats: stats for uncached hits
            cstats,ucstats = get_statscounter(self)

            # get dict with caching limits
            climits = get_cachinglimits(self,f.func_name)

            try:
                (cachedArgs,cachedTimestamps) = self._function_cache[f]
                if input_values == self._property_input_cache[f]:
                    try:
                        x = cachedArgs[fun_input]
                        if not climits.get('nocache'):
                            stats_increment(cstats,f)
                            cachedTimestamps[fun_input] = time.time()
                            return x
                    except AttributeError:
                        pass
                    except KeyError:
                        pass
            except AttributeError:
                self._property_input_cache = {}
                self._function_cache = {}
            except KeyError:
                pass

            try:
                fdict,tdict = self._function_cache[f]
            except KeyError:
                fdict = {}
                tdict = {}
                self._function_cache[f] = (fdict,tdict)

            x = fdict[fun_input] = f(self,*args,**kwargs)
            tdict[fun_input] = time.time()

            self._property_input_cache[f] = input_values

            numCache = climits.get('maxNCached')
            if numCache is not None:
                if len(fdict) > numCache:
                    print("sorted")
                    timeSorted = sorted(tdict.items(), key=operator.itemgetter(1))
                    print(timeSorted)
                    print("-sorted")
                    for k,v in timeSorted:
                        if len(fdict) > numCache:
                            #print("new result %s"%x)
                            #print("Delete %s"%k)
                            del fdict[k]
                            del tdict[k]
                        else:
                            break

            stats_increment(ucstats,f)
            return x
        return get
    return smart_cm

def stats_increment(stats,f):
    if stats is not None:
        fstats = stats.get(f)
        if fstats is None:
            fstats = 0
        stats[f] = fstats + 1

def get_statscounter(obj):
    # statistics for chached returns
    try:
        cstats = obj._smart_cached_stats
    except AttributeError:
        cstats = None

    # statistics for uncached returns
    try:
        ucstats = obj._smart_uncached_stats
    except AttributeError:
        ucstats = None
    return cstats,ucstats

def get_cachinglimits(obj,fname):
    # limits
    try:
        climits = obj._smart_cached_limits
        # check for limits for current function
        return climits[fname]
    except Exception as e:
        return {}

class CacheStats(object):
    def __init__(self):
        self._smart_cached_stats={}
        self._smart_uncached_stats={}

class CacheLimits(object):
    validKeyValues = {"nocache":bool,
                      "maxNCached": int
                      }
    def __init__(self):
        self._smart_cached_limits = {}

    def __isValid(self,key,value):
        if not type(value) == CacheLimits.validKeyValues[key]:
            raise TypeError("Wrong type for key: %s"%key)

    def set_cachelimit(self,function,key,value):
        self.__isValid(key,value)
        fDict = None
        try:
            fDict = self._smart_cached_limits[function]
        except AttributeError:
            self._smart_cached_limits = {}
        if fDict is None:
            fDict = {}
            self._smart_cached_limits[function] = fDict
        fDict [key] = value
