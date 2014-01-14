################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################

from pyretic.core.language import Filter, match, Query, FwdBucket, CountBucket
from pyretic.lib.query import counts, packets

class CharacterGenerator:
    """ Generate characters to represent equivalence classes of existing match
    predicates. `get_token` returns the same token value as before if a policy
    already seen (and hence recorded in its map) is provided to it.
    """
    token = 32 # start with printable ASCII for visual inspection ;)
    filter_to_token = {}
    token_to_filter = {}
    
    def __init__(self):
        self.filter_to_token = CharacterGenerator.filter_to_token
        self.token_to_filter = CharacterGenerator.token_to_filter
        self.token = CharacterGenerator.token

    def get_token(self, pol):
        if pol in self.filter_to_token:
            token = self.filter_to_token[pol]
            return token
        else:
            new_token = self.__new_token__()
            self.filter_to_token[pol] = new_token
            self.token_to_filter[new_token] = pol
            return new_token

    def __new_token__(self):
        self.token += 1
        return self.token

class path(Query):
    """A way to query packets or traffic volumes satisfying regular expressions
    denoting paths of located packets.
    """
    def __init__(self):
        print "to do, still."

class atom(path, Filter):
    """A single atomic match in a path expression.
    
    :param m: a Filter (or match) object used to initialize the path atom.
    :type match: Filter
    """
    def __init__(self, m):
        if isinstance(m, Filter):
            self.policy = m
        else:
            raise TypeError
        super(atom, self).__init__()
        self._token = None

    @property
    def token(self):
        """ Generates a token with its policy. This property is only used in the
        context of using this object as a `path` instance, not an `atom`
        instance.
        
        The token property cannot be set from outside this method.
        """
        if not self._token:
            cg = CharacterGenerator()
            self._token = cg.get_token(self.policy)
        return self._token

    def __and__(self, other):
        if isinstance(other, atom):
            self.policy = self.policy & other.policy
            assert isinstance(self.policy, Filter)
            return self
        else:
            raise TypeError

    def __or__(self, other):
        # This won't actually work because the '+' operation results in an
        # object of type parallel, which is not a Filter.
        if isinstance(other, atom):
            self.policy = self.policy + other.policy
            assert isinstance(self.policy, Filter)
            return self
        else:
            raise TypeError

    def __sub__(self, other):
        if isinstance(other, atom):
            self.policy = (~other.policy) & self.policy
            assert isinstance(self.policy, Filter)
            return self
        else:
            raise TypeError

    def __invert__(self):
        negated = ~(self.policy)
        if isinstance(negated, Filter):
            return atom(negated)
        else:
            raise TypeError

