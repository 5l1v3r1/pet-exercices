# -*- coding: utf-8 -*-

from __future__ import print_function

from time import time


def benchmark(f):
    def _wrapper(*args, **kwargs):
        t = time()
        r = f(*args, **kwargs)
        BenchmarkResults.results.append(time() - t)
        return r
    return _wrapper


class BenchmarkResults(object):
    results = []
    
    @classmethod
    def average(cls):
        return sum(cls.results)/len(cls.results)
