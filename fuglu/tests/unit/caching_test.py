import unittest
from fuglu.extensions.caching import smart_cached_memberfunc, smart_cached_property, CacheLimits, CacheStats

class CachingTests(unittest.TestCase):
    def test_cachedProperty(self):
        """
        Test caching of class property calculation
        """
        class CachedTest(object):
            """Dummy test class with property caching"""
            def __init__(self,a,b):
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

    def test_cachedMemberfunc(self):
        """
        Test caching of member function return value.
        """
        class CachedTest(object):
            """Text class using caching for member function"""
            def __init__(self,a,b):
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
        a =c.aPlus10bPlusX(10)
        a =c.aPlus10bPlusX(11)
        a =c.aPlus10bPlusX(12)
        a =c.aPlus10bPlusX(13)
