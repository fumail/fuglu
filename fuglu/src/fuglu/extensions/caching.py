import functools

def smart_cached_property(inputs=[]):
    # from -> http://code.activestate.com/recipes/576563-cached-property/?in=user-4167995#c4
    def smart_cp(f):
        @functools.wraps(f)
        def get(self):
            input_values = dict((key,getattr(self,key)) for key in inputs )
            try:
                x = self._property_cache[f]
                if input_values == self._property_input_cache[f]:
                    return x
            except AttributeError:
                self._property_cache ={}
                self._property_input_cache = {}
            except KeyError:
                pass

            x = self._property_cache[f] = f(self)
            self._property_input_cache[f] = input_values

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
            try:
                cachedArgs = self._function_cache[f]
                if input_values == self._property_input_cache[f]:
                    try:
                        x = cachedArgs[fun_input]
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
                fdict = self._function_cache[f]
            except KeyError:
                fdict = {}
                self._function_cache[f] = fdict
            x = fdict[fun_input] = f(self,*args,**kwargs)
            self._property_input_cache[f] = input_values

            return x
        return get
    return smart_cm

