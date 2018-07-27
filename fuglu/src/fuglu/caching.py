# -*- coding: utf-8 -*-
#   Copyright 2009-2018 Fumail Project
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
#
#
import functools
import time
import operator

#--
# For examples check the tests in "caching_test.py"
#--

def smart_cached_property(inputs=[]):
    """
    The decorator to create a cached property. The property will be recalculated if
    one of the class members (as defined in the input-list) has changed.

    Args:
        inputs (list of strings): list of string with member names this property depends on

    Returns:
        decorated function

    """
    # Base idea is from
    # http://code.activestate.com/recipes/576563-cached-property/?in=user-4167995#c4
    # but then extended for stats and limits
    def smart_cp(f):
        @functools.wraps(f)
        def get(self):
            input_values = dict((key,getattr(self,key)) for key in inputs )

            #  cstats: stats for cached hits
            # ucstats: stats for uncached hits
            cstats,ucstats = get_statscounter(self)

            # get dict with caching limits
            try:
                # Py 2
                climits = get_cachinglimits(self,f.func_name)
            except AttributeError:
                # Py 3
                climits = get_cachinglimits(self,f.__name__)

            try:
                __property_cache = self._property_cache
            except AttributeError:
                __property_cache = {}
                self._property_cache = __property_cache

            try:
                __property_input_cache = self._property_input_cache
            except AttributeError:
                __property_input_cache = {}
                self._property_input_cache = __property_input_cache

            try:
                x = __property_cache[f]
                if input_values == __property_input_cache[f]:
                    stats_increment(cstats,f)
                    return x
            except KeyError:
                pass

            x = f(self)

            try:
                func_allow_cache = climits.get('function')()
            except Exception:
                func_allow_cache = True

            #---   ---#
            #- cache -#
            #---   ---#
            if not climits.get('nocache') and func_allow_cache:
                __property_cache[f] = x
                __property_input_cache[f] = input_values

            stats_increment(ucstats,f)

            return x
        return property(get)
    return smart_cp

def smart_cached_memberfunc(inputs=[]):
    """
    Decorate a class member function to cache its return values. A list of class members
    can be given. If one of the members in this list changes the return value will
    be recalculated even if previously cached. For each set of inputs (for the decorated function) a cached
    value will be created. This can be limited by using the Cachelimits and define "max_ncached".

    Args:
        inputs (list of strings): list of string with member names this function depends on

    Returns:
        decorated function

    """
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
            try:
                # Python 2
                climits = get_cachinglimits(self,f.func_name)
            except AttributeError:
                # Python 3
                climits = get_cachinglimits(self,f.__name__)

            try:
                __function_cache = self._function_cache
            except AttributeError:
                __function_cache = {}
                self._function_cache = __function_cache

            try:
                __property_input_cache = self._property_input_cache
            except AttributeError:
                __property_input_cache = {}
                self._property_input_cache = __property_input_cache

            try:
                (cached_args,cached_timestamps) = __function_cache[f]
                if input_values == __property_input_cache[f]:
                    x = cached_args[fun_input]

                    stats_increment(cstats,f)
                    cached_timestamps[fun_input] = time.time()
                    return x
            except KeyError as e:
                pass

            try:
                # "fdict" stores the function result based on the function input
                # "tdict" stores the last call time of the function for given function input
                #
                # with function input beying a list storing args + keyword args
                fdict,tdict = __function_cache[f]
            except KeyError:
                fdict = {}
                tdict = {}
                __function_cache[f] = (fdict,tdict)

            x = f(self,*args,**kwargs)

            try:
                func_allow_cache = climits.get('function')()
            except Exception:
                func_allow_cache = True

            #---   ---#
            #- cache -#
            #---   ---#
            if not climits.get('nocache') and func_allow_cache:
                #----
                #-- cache function call, result and call time
                #----
                fdict[fun_input] = x
                tdict[fun_input] = time.time()

                __property_input_cache[f] = input_values

                num_cache = climits.get('max_ncached')
                if num_cache is not None:
                    #----
                    #-- Limit number of cached results
                    #----
                    if len(fdict) > num_cache:
                        time_sorted = sorted(tdict.items(), key=operator.itemgetter(1))
                        # for debugging
                        # print(time_sorted)
                        for k,v in time_sorted:
                            if len(fdict) > num_cache:
                                # for debugging
                                # print("new result %s"%x)
                                # print("Delete %s"%k)
                                del fdict[k]
                                del tdict[k]
                            else:
                                break

            stats_increment(ucstats,f)
            return x
        return get
    return smart_cm

def stats_increment(stats,f):
    """
    Increments the statistic counters for cached or uncached calls

    Args:
        stats (dict): statistics counter dict (counting cached or uncached calls)
        f (wrapped function): function wrapped

    """
    if stats is not None:
        fstats = stats.get(f)
        if fstats is None:
            fstats = 0
        stats[f] = fstats + 1

def get_statscounter(obj):
    """
    Returns statistic counters if available in class (which is the case if class
    has been derived from Cachestats)

    Args:
        obj (instance): object instance

    Returns:
        (dict,dict) : Tuple containing counter dicts if available or None otherwise

    """
    # statistics for cached returns
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
    """
    For a given function name, get caching limits as defined by user

    Args:
        obj (instance): object instance
        fname (string): string containing function name wrapped by smart_caching

    Returns:
        dict: dictionary with caching limitations

    """
    # limits
    try:
        climits = obj._smart_cached_limits
        # check for limits for current function
        return climits[fname]
    except Exception as e:
        return {}

class Cachestats(object):
    """
    Class storing dicts and routines for caching statistics. Derive your
    class from this class to be able to extract and print statistics of
    cachec/uncached calls...
    """
    def __init__(self):
        self._smart_cached_stats={}
        self._smart_uncached_stats={}

    def match_dicts(self):
        """
        Match dictionary keys making sure they exist in the cached and uncached statistics dicts
        which makes it easy to print a summary
        """
        # make sure all keys from cached calls are in uncached calls
        # (which really should be the case!)
        for k,v in iter(self._smart_cached_stats.items()):
            v2 = self._smart_uncached_stats.get(k)
            if v2 is None:
                self._smart_uncached_stats[k] = 0

        # make sure all keys from uncached calls are in cached calls
        for k,v in iter(self._smart_uncached_stats.items()):
            v2 = self._smart_cached_stats.get(k)
            if v2 is None:
                self._smart_cached_stats[k] = 0

    def get_cachestats(self):
        """
        Get list of tuples storing caching use.

        Returns:
            list: List of tuples (func name, cached calls, uncached calls)

        """
        self.match_dicts()
        statsList = []
        for k,vcached in iter(self._smart_cached_stats.items()):
            try:
                fname = k.func_name
            except AttributeError:
                try:
                    fname = k.__name__
                except Exception as e:
                    raise e
            except Exception as e:
                fname = k
            statsList.append((fname, self._smart_cached_stats[k], self._smart_uncached_stats[k]))
        return statsList

    def string_cachestats(self):
        """Get string containing caching statistics"""

        # make sure dicts are consistent
        self.match_dicts()

        string =  "---------------------\n"\
                 +"- Cache statistics: -\n"\
                 +"---------------------\n" \
                 +"\n"
        for k,vCached in iter(self._smart_cached_stats.items()):
            try:
                fname = k.func_name
            except AttributeError:
                try:
                    fname = k.__name__
                except Exception as e:
                    raise e
            except Exception as e:
                fname = k
            string += "Calls for \"%s\": (cached/uncached) = (%u/%u)\n"%(fname,
                                                                self._smart_cached_stats[k],
                                                                self._smart_uncached_stats[k])
        return string

class Cachelimits(object):
    """
    This class allows to define class-specific caching limitations. Derive your class
    from this class and use the "set_cachelimit" function to define caching limitations.

    Current valid options are:
    nocache:    True/False to enable/disable creating new cached values
    max_ncached: Integer to limit the number of cached values for different function arguments
    function:   A callable object (function,instancemethod) returning True/False
                The function is called AFTER calculating a result. So once a result is in the cache
                it will remain. The function decides if a newly calculated value will be put in cache
                or not.
    """
    valid_keyvalues = {"nocache":bool,
                      "max_ncached": int,
                      "function": None
                       }

    def __init__(self):
        self._smart_cached_limits = {}

    def __is_valid(self, key, value):
        """Check validity of limit"""
        if key not in Cachelimits.valid_keyvalues:
            raise ValueError("Cachelimit \"%s\" not supported!"%key)

        if key == "function":
            if not callable(value):
                raise TypeError("Function object for \"%s\" is not callable!"%key)
        elif not type(value) == Cachelimits.valid_keyvalues[key]:
            raise TypeError("Wrong type for key \"%s\""%key)

    def set_cachelimit(self,function,key,value):
        """
        Set a caching limit

        Args:
            function (string): The name of the function to apply the limit to
            key (string): the limit to apply, see valid options in the class description
            value (string,int,callable object): the value to apply, see options in class description

        """
        self.__is_valid(key, value)
        f_dict = None
        try:
            f_dict = self._smart_cached_limits[function]
        except AttributeError:
            self._smart_cached_limits = {}
        except KeyError:
            pass

        if f_dict is None:
            f_dict = {}
            self._smart_cached_limits[function] = f_dict
        f_dict[key] = value
