
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
    

def test_Data():
    class RecordTest(Data("id bob foo bar")): pass

    x = RecordTest(id=None, bob=3, foo="hey", bar=None)

    assert x.bob is 3
    assert x.id is None
    assert hasattr(x, "id")
    assert hasattr(x, "bob")
    assert hasattr(x, "foo")
    assert hasattr(x, "bar")


def test_Case():
    class Branch(Data("left right")): pass
    class Node(Data("value")): pass

    tree = Branch(Branch(Node(1), Node(2)), Node(6))

    class tree_len(Case):
        def case_Node(self, node):
            return 1

        def case_Branch(self, branch):
            return 1 + self(branch.left) + self(branch.right)

    assert tree_len()(tree) == 5


def test_frozendict():
    d = frozendict(a="hi", b=4)

    assert d["a"] == "hi"
    assert d["b"] == 4

    assert d.get("c", "hello") == "hello"

    assert d.update(c="meow").get("c", "hello") == "meow"

    # Test mutation didn't screw us up
    assert d.get("c", "hello") == "hello"

    assert len(d) == 2
    
