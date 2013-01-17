from networkx import *
from sets import *
import random 

"""MinimumSpanningTree.py

Kruskal's algorithm for minimum spanning trees. D. Eppstein, April 2006, modified by Joel Miller May 2007.

Other algorithms for minimum spanning trees J. Miller May 2007, see http://www.ics.uci.edu/~eppstein/161/960206.html for descriptions
"""

"""UnionFind.py

Union-find data structure. Based on Josiah Carlson's code,
http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/215912
with significant additional changes by D. Eppstein.
"""

class UnionFind:
    """Union-find data structure.

    Each unionFind instance X maintains a family of disjoint sets of
    hashable objects, supporting the following two methods:

    - X[item] returns a name for the set containing the given item.
      Each set is named by an arbitrarily-chosen one of its members; as
      long as the set remains unchanged it will keep the same name. If
      the item is not yet part of a set in X, a new singleton set is
      created for it.

    - X.union(item1, item2, ...) merges the sets containing each item
      into a single larger set.  If any item is not yet part of a set
      in X, it is added to X as one of the members of the merged set.
    """

    def __init__(self):
        """Create a new empty union-find structure."""
        self.weights = {}
        self.parents = {}

    def __getitem__(self, object):
        """Find and return the name of the set containing the object."""

        # check for previously unknown object
        if object not in self.parents:
            self.parents[object] = object
            self.weights[object] = 1
            return object

        # find path of objects leading to the root
        path = [object]
        root = self.parents[object]
        while root != path[-1]:
            path.append(root)
            root = self.parents[root]

        # compress the path and return
        for ancestor in path:
            self.parents[ancestor] = root
        return root
        
    def __iter__(self):
        """Iterate through all items ever found or unioned by this structure."""
        return iter(self.parents)

    def union(self, *objects):
        """Find the sets containing the objects and merge them all."""
        roots = [self[x] for x in objects]
        heaviest = max([(self.weights[r],r) for r in roots])[1]
        for r in roots:
            if r != heaviest:
                self.weights[heaviest] += self.weights[r]
                self.parents[r] = heaviest

#Kruskal's algorithm: "borrowed" (along with UnionFind) from
#http://www.ics.uci.edu/~eppstein/PADS/ by Joel Miller.  The only
#edits I have done are to change the way the edges are found to be
#consistent with the networkx format, to include the weight with each
#edge, and to return the tree, rather than a list of edges in the
#tree.


def Kruskal(G):
    """
    Return the minimum spanning tree of an undirected graph G.
    G should be represented in such a way that G[u][v] gives the
    length of edge u,v, and G[u][v] should always equal G[v][u].
    The tree is returned as a list of edges.
    """
    
    # Kruskal's algorithm: sort edges by weight, and add them one at a time.
    # We use Kruskal's algorithm, first because it is very simple to
    # implement once UnionFind exists, and second, because the only slow
    # part (the sort) is sped up by being built in to Python.
    subtrees = UnionFind()
    tree_edges = []
#    edges = [(W,u,v) for (u,v,W) in G.edges()] 
    edges = [(1,u,v) for (u,v) in G.edges()] 
#    edges.sort()
    random.shuffle(edges)
    for W,u,v in edges:
        if subtrees[u] != subtrees[v]:
#            tree_edges.append((u,v,W))   
            tree_edges.append((u,v))   
            subtrees.union(u,v)
    tree = nx.Graph()
    tree.add_edges_from(tree_edges)

    if G.order()==1:
        tree.add_node(G.nodes()[0])
    return tree        




def Prim(G):
    found = {}
    for node in G.nodes():
        found[node]=False#found says whether we've put the node into T
    u=G.nodes()[0]
    
    T=nx.Graph()
    T.add_node(u)
    found[u]=True 
#    invertededgelist = [(W,u,v) for (u,v,W) in G.edges(u)]#this depends on the
    invertededgelist = [(1,u,v) for (u,v) in G.edges(u)]#this depends on the
                                                  #fact that each edge
                                                  #of the list
                                                  #returned by
                                                  #.edges(u) starts
                                                  #with u
    invertededgelist.sort()
    while T.order()<G.order():
        (W,t,v) = invertededgelist.pop(0) #t in T, v not in T yet
#        T.add_edge(v,t,W)
        T.add_edge(v,t)
        found[v]=True
#        for (v,u,W) in G.edges(v):
        for (v,u) in G.edges(v):
            W=1
            if not found[u]:
                edge_exists = False #tests for whether an edge from u to T exists
                for (X,a,b) in invertededgelist:
                    if b==u:
                        edge_exists=True
                        if W<X:
                            invertededgelist.remove((X,a,b))
                            invertededgelist.append((W,v,u))
                            break
                if not edge_exists:
                    invertededgelist.append((W,v,u))
                    
                        
        invertededgelist.sort()#hopefully this is a sort which runs
                               #quicker if list is almost all in the
                               #right order.
    return T
                        
                        
    
def Boruvka(G): #modification of that found on eppstein's webpage.
                #loops through edges, not nodes.  I sort the edges,
                #then iteratively find the edges that need to be
                #added.  Each loop should find the same edges as
                #Boruvka, but it finds them through a different
                #technique than the webpage suggests.
    subtrees = UnionFind()
    T=nx.Graph()
    N=G.order()
    E=0
    edgelist = G.edges()
    tmpedgelist = [(W,u,v) for (u,v,W) in edgelist]
    tmpedgelist.sort()
    edgelist = [(u,v,W) for (W,u,v) in tmpedgelist]
    while N-E>1:#while T still needs more edges
        minimum_edges={} #min edge for each subtree
        removal_list = []
        for (u,v,W) in edgelist:
                if subtrees[u]!=subtrees[v]:
                    if not minimum_edges.has_key(subtrees[u]):
                        minimum_edges[subtrees[u]]=(u,v,W)
                    if not minimum_edges.has_key(subtrees[v]):
                        minimum_edges[subtrees[v]]=(u,v,W)
                    if len(minimum_edges.keys())==N-E:
                        break  
                else:
                    removal_list.append((u,v,W)) #don't look at an edge in
                                             #same component again
        for edge in removal_list:
            edgelist.remove(edge)
        for edge in Set(minimum_edges.values()):#I use set to avoid deleting edge twice
            subtrees.union(edge[0],edge[1])
            T.add_edge(edge)
            edgelist.remove(edge)
        E=T.size()
    if G.order()==1:
        T.add_node(G.nodes()[0])
    return T
            
