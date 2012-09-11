
from frenetic.generators import *
from itertools import *
import time

r = ["first", "second", "third", "fourth"]

def delaygen1():
    yield "first"
    time.sleep(0.5)
    yield "fourth"

def delaygen2():
    time.sleep(0.1)
    yield "second"
    time.sleep(0.25)
    yield "third"

def test_merge():
    
    l = list(merge(delaygen1(), delaygen2()))
    l2 = list(merge(delaygen2(), delaygen1()))

    assert l == r
    assert l2 == r

def test_merge_hold():
    l = list(merge_hold(delaygen1(), delaygen2()))

    assert l == [("first", "second"), ("first", "third"), ("fourth", "third")]


def test_Event():
    x = Event()

    e = iter(x)

    x.signal("first")
    x.signal("second")
    x.signal("third")
    x.signal("fourth")

    assert list(islice(e, 4)) == r
    
