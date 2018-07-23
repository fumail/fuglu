import unittest
from fuglu.extensions.caching import smart_cached_memberfunc, smart_cached_property, CacheLimits, CacheStats

class CachingTests(unittest.TestCase):
    def test_cachedProperty(self):
        """
        Test caching of class property calculation
        """
        class CachedTest(CacheStats):
            """Dummy test class with property caching"""
            def __init__(self,a,b):
                super(CachedTest,self).__init__()
                self.a = a
                self._b = b
                self.depVar_count = 0
                self.depVar2_count = 0
                self.aPlusX_count = 0
            @smart_cached_property(inputs=['a','b'])
            def depVar(self):
                print("Calculating depVar")
                self.depVar_count += 1
                return self.a*self.b

            @smart_cached_property(inputs=['depVar'])
            def depVar2(self):
                print("Calculating depVar2")
                self.depVar2_count += 1
                return self.depVar + 1

            @property
            def b(self):
                return self._b

            @b.setter
            def b(self,val):
                self._b = val

        c = CachedTest(2,3)
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(1,c.depVar_count,"First call")
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(1,c.depVar_count,"Now value should be cached")
        self.assertEqual(c.a*c.b+1,c.depVar2)
        self.assertEqual(1,c.depVar2_count,"First call to second function")

        c.b = 4
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(2,c.depVar_count,"New value set by property decorator triggers calculation")
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(2,c.depVar_count,"Now value should be in cached")

        c.a = 5
        self.assertEqual(c.a*c.b+1,c.depVar2)
        self.assertEqual(3,c.depVar_count,"Function 2 requires property 1 which should be recalculated since porperty has changed")
        self.assertEqual(2,c.depVar2_count,"Function 2 is recaluculated because it depends on first property which was recalculated")
        c.a = 5
        self.assertEqual(c.a*c.b+1,c.depVar2)
        self.assertEqual(3,c.depVar_count,"Setting same value should not trigger rebuilt")
        self.assertEqual(2,c.depVar2_count,"Setting same value should not trigger rebuilt")

        # print cache stats on screen
        print(c.string_CacheStats())

    def test_cachedMemberfunc(self):
        """
        Test caching of member function return value.
        """
        class CachedTest(CacheStats):
            """Text class using caching for member function"""
            def __init__(self,a,b):
                super(CachedTest,self).__init__()
                self.a = a
                self._b = b
                self.aPlus10bPlusX_count = 0

            @property
            def b(self):
                return self._b
            @b.setter
            def b(self,val):
                self._b = val

            @smart_cached_memberfunc(inputs=['a','b'])
            def aPlus10bPlusX(self,x):
                print("Calculating aPlusX")
                self.aPlus10bPlusX_count += 1
                return self.a + 10*self.b + x

        c = CachedTest(2,3)

        print("--------------------")
        print("--- a + 10*b + x ---")
        print("--------------------")
        add = 10
        self.assertEqual(c.a+10*c.b+add,c.aPlus10bPlusX(add))
        self.assertEqual(1,c.aPlus10bPlusX_count,"First call should trigger recalculation")
        self.assertEqual(c.a+10*c.b+add,c.aPlus10bPlusX(add),"First call should trigger recalculation")
        self.assertEqual(1,c.aPlus10bPlusX_count,"Should be cached")
        c.a = 6
        self.assertEqual(c.a+10*c.b+add,c.aPlus10bPlusX(add))
        self.assertEqual(2,c.aPlus10bPlusX_count,"New member var should trigger recalculation")
        self.assertEqual(2,c.aPlus10bPlusX_count,"Should be cached")
        add2 = 20
        self.assertEqual(c.a+10*c.b+add2,c.aPlus10bPlusX(add2))
        self.assertEqual(3,c.aPlus10bPlusX_count,"New function value should trigger recalculation")

        self.assertEqual(c.a+10*c.b+add,c.aPlus10bPlusX(add))
        self.assertEqual(3,c.aPlus10bPlusX_count,"This was already calculated")
        c.b = 100
        self.assertEqual(c.a+10*c.b+add,c.aPlus10bPlusX(add))
        self.assertEqual(4,c.aPlus10bPlusX_count,"Changing member by decorator should trigger recalculation")

        # print cache stats on screen
        print(c.string_CacheStats())

    def test_nocach(self):
        """
        Test caching of class property calculation
        """
        class CachedTest(CacheStats,CacheLimits):
            """Dummy test class with property caching"""
            def __init__(self,a,b):
                super(CachedTest,self).__init__()
                self.a = a
                self.b = b
                self.depVar_count = 0

                # disable caching for function "depVar"
                self.set_cachelimit("depVar","nocache",True)

            @smart_cached_property(inputs=['a','b'])
            def depVar(self):
                print("Calculating depVar")
                self.depVar_count += 1
                return self.a*self.b

        c = CachedTest(2,3)
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(1,c.depVar_count,"First call")
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(2,c.depVar_count,"Now value should not be cached")
        c.set_cachelimit("depVar","nocache",False)
        self.assertEqual(2,c.depVar_count,"Now value should be taken from cache")

        # print cache stats on screen
        print(c.string_CacheStats())


    def test_cachedMemberfunc_limits(self):
        """
        Test caching of member function return value.
        """
        class CachedTest(CacheStats,CacheLimits):
            """Text class using caching for member function"""
            def __init__(self,a,b):
                super(CachedTest,self).__init__()
                self.a = a
                self._b = b
                self.aPlus10bPlusX_count = 0
                self.set_cachelimit("aPlus10bPlusX","maxNCached",2)
            @property
            def b(self):
                return self._b
            @b.setter
            def b(self,val):
                self._b = val

            @smart_cached_memberfunc(inputs=['a','b'])
            def aPlus10bPlusX(self,x):
                print("Calculating aPlusX")
                self.aPlus10bPlusX_count += 1
                return self.a + 10*self.b + x

        c = CachedTest(2,3)

        print("--------------------")
        print("--- a + 10*b + x ---")
        print("--------------------")
        val = 10
        self.assertEqual(c.a + 10*c.b + val, c.aPlus10bPlusX(val))
        self.assertEqual(1,c.aPlus10bPlusX_count,'First time called')
        val = 21
        self.assertEqual(c.a + 10*c.b + val, c.aPlus10bPlusX(val))
        self.assertEqual(2,c.aPlus10bPlusX_count,'First time for this argument called')
        self.assertEqual(c.a + 10*c.b + val, c.aPlus10bPlusX(val))
        self.assertEqual(2,c.aPlus10bPlusX_count,'Second time for this argument called')
        val = 32
        self.assertEqual(c.a + 10*c.b + val, c.aPlus10bPlusX(val))
        self.assertEqual(3,c.aPlus10bPlusX_count,'First time for this argument called')

        print("now the first result should have been removed from cache")
        val = 10
        self.assertEqual(c.a + 10*c.b + val, c.aPlus10bPlusX(val))
        self.assertEqual(4,c.aPlus10bPlusX_count,'Second time called but should not be in cache anymore')

        # print cache stats on screen
        print(c.string_CacheStats())

    def test_nocachfunc(self):
        """
        Test caching of class property calculation, using a member function
        defining if cache value should be used or not
        """
        class CachedTest(CacheStats,CacheLimits):
            """Dummy test class with property caching"""
            def __init__(self,a,b):
                super(CachedTest,self).__init__()
                self.a = a
                self.b = b
                self.depVar_count = 0
                self.state = "open"

                # disable caching for function "depVar"
                self.set_cachelimit("depVar","function",self.doIwant2cache)

            @smart_cached_property(inputs=['a','b'])
            def depVar(self):
                print("Calculating depVar")
                self.depVar_count += 1
                return self.a*self.b

            def doIwant2cache(self):
                # as long as state is equal to open there
                # should be no caching. If the state is not
                # open, then return the cached result if available
                return not self.state == "open"

        c = CachedTest(2,3)
        c.state = "open" # shop is open, do work
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(1,c.depVar_count,"Don't cache")
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(2,c.depVar_count,"Don't cache")
        c.state = "close" # shop is closed, minimize work, cache and use cached value
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(3,c.depVar_count,"Value noe in cache yet")
        self.assertEqual(c.a*c.b,c.depVar)
        self.assertEqual(3,c.depVar_count,"Use cache")

        # print cache stats on screen
        print(c.string_CacheStats())

    def test_nocachfunc_size(self):
        """
        Tests cached member func with the example of a object size limitation
        """
        class CachedTest(CacheStats,CacheLimits):
            """Dummy test class with property caching and size limitation"""
            def __init__(self,a,b):
                super(CachedTest,self).__init__()
                self.archiveList = {"a.zip":100,
                                    "b.zip":200,
                                    "c.zip":50}
                self._currentSize = 0
                self._newSize     = 0
                self.limitSize    = 200
                self.getCounter   = 0

                # disable caching for function "depVar"
                self.set_cachelimit("get","function",self.doIwant2cache)

            @property
            def currentSize(self):
                return self._currentSize

            @currentSize.setter
            def currentSize(self,value):
                print("changing currentSize from %u to %u"%(self.currentSize,value))
                self._currentSize = value

            @smart_cached_memberfunc(inputs=[])
            def get(self,fname):
                self.getCounter += 1
                self.newSize = self.currentSize + self.archiveList[fname]
                if self.newSize <= self.limitSize:
                    self.currentSize = self.newSize
                return self.archiveList[fname]

            def doIwant2cache(self):
                print("%u <= %u : %s"%(self.newSize,self.limitSize,self.newSize <= self.limitSize))
                return (self.newSize <= self.limitSize)

        c = CachedTest(2,3)
        self.assertEqual(0,c.getCounter,"start with zero counter")
        self.assertEqual(c.archiveList['a.zip'],c.get('a.zip'))
        self.assertEqual(1,c.getCounter,"a.zip is not cached yet")
        self.assertEqual(c.archiveList['a.zip'],c.get('a.zip'))
        self.assertEqual(1,c.getCounter,"now a.zip should be from cache")
        self.assertEqual(c.archiveList['b.zip'],c.get('b.zip'))
        self.assertEqual(2,c.getCounter,"b.zip is not cached will not be cached because total size becomes too big")
        self.assertEqual(c.archiveList['b.zip'],c.get('b.zip'))
        self.assertEqual(3,c.getCounter,"b.zip is not in cache and will not be cached")
        self.assertEqual(c.archiveList['c.zip'],c.get('c.zip'))
        self.assertEqual(4,c.getCounter,"c.zip is not cached yet")
        self.assertEqual(c.archiveList['c.zip'],c.get('c.zip'))
        self.assertEqual(4,c.getCounter,"c.zip should be taken from cache")

        # print cache stats on screen
        print(c.string_CacheStats())
