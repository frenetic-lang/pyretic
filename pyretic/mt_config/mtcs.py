
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

MAX_STAGES=13 # max. for the extensively multi-staged pipeline 'mt'

class pipeline_config(object):
    def __init__(self, num_tables):
        self.num_tables = num_tables
        self.edges = {}

    def add_edge(self, src, dst):
        assert 0 <= src < dst < self.num_tables
        self.edges[src] = dst

    def __repr__(self):
        out  = "Pipeline configuration:\n"
        out += "Number of tables: %d\n" % self.num_tables
        out += "Edges:\n%s" % str(self.edges)
        return out

def path_query_pipeline():
    """ Create a pipeline configuration for path queries. This pipeline has a
    structure:

    (virtual_tagging >>
     in_tagging + in_capture) ->
    forwarding ->
    ((out_tagging + out_capture) >>
     virtual_untagging)
    """
    pqc = pipeline_config(6)
    for i in range(0, 5):
        pqc.add_edge(i, i+1)
    return pqc

def mt():
    """Pipeline configuration for multi-stage path query policies, with 30 packet
    processing stages overall. This is an extensively multi-staged, but
    deterministic, pipeline.
    up_capture >> virtual_tagging >> ingress_table_stage_0 >> ... >> stage 13
    >>
    forwarding >>
    egress_table_stage_0 >> ... >> stage 13 >> virtual_untagging
    """
    num_tables = (2*MAX_STAGES) + 4
    mt = pipeline_config(num_tables)
    for i in range(0, num_tables-1):
        mt.add_edge(i, i+1)
    return mt

def default_pipeline():
    """ Create a default, "testing" configuration for nicira extension
    mode. This does a simple "multi-table" configuration which looks like:

    redirect to table 1 ->
    actual table with ALL forwarding rules
    """
    dc = pipeline_config(2)
    dc.add_edge(0, 1)
    return dc

def consistent_update_config():
    """ Can't do this with the current pipeline config class. Need per-rule
    next-table structures.
    """
    return None
