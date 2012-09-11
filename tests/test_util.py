
from frenetic.util import *


def test_Record():
    class RecordTest(Record):
        _fields = "id bob foo bar"

    x = RecordTest("abc", "def", "hij", "klm")
    assert x.bob == "def"
        
    x = RecordTest(id=None, bob=3, foo="hey", bar=None)

    assert x.bob is 3
    assert x.id is None
    assert hasattr(x, "id")
    assert hasattr(x, "bob")
    assert hasattr(x, "foo")
    assert hasattr(x, "bar")

    class RecordInherit(RecordTest):
        _fields = "hope this works"

    x = RecordInherit(None, None, None, None, None, None, None)

    assert x.hope is None
    assert hasattr(x, "bob")
    assert hasattr(x, "hope")
    assert hasattr(x, "this")
    assert hasattr(x, "works")


def test_Record_override():
    class RecordTest(Record):
        _fields = "lame"
        def __new__(cls, lame=None):
            return Record.__new__(cls, lame)

    assert RecordTest().lame is None


    
    
def test_Data():
    class RecordTest(Data("id bob foo bar")): pass

    x = RecordTest(id=None, bob=3, foo="hey", bar=None)

    assert x.bob is 3
    assert x.id is None
    assert hasattr(x, "id")
    assert hasattr(x, "bob")
    assert hasattr(x, "foo")
    assert hasattr(x, "bar")



def test_frozendict():
    d = frozendict(a="hi", b=4)

    assert d["a"] == "hi"
    assert d["b"] == 4

    assert d.get("c", "hello") == "hello"

    assert d.update(c="meow").get("c", "hello") == "meow"

    # Test mutation didn't screw us up
    assert d.get("c", "hello") == "hello"

    assert len(d) == 2
    
