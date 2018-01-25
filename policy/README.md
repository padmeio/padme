
PADME Policy Go Module

The policy package is an articulation of the PADME Policy definition.

The emphasis in this code (at present) is to articulate the design 
and to ensure architectural/design correctness rather than go code 
optimality. (The latter can be accomplished as we go).

At present the full stack (Rule to Bundle is present).  Examples of 
its use can be found in the tests (especially the PolicyBundle tests).

At present the following are our highest priorities in terms of todos:
- policy serialization/deserialization to json
- a predefined set of layer name constants
- expanded matching infrastructure

After this:
- expansion and filling in of the IdentifiedBy component
- elaboration of the plugin infrastructure
- cosntruction of a basic enforcer

An Elaboration of Rule Matchers
At present the rule matcher does a simple string compare of 
two rule patterns.  This needs to be expanded with different
matchers that support wildcarding and the like. Support for
different matchers for each different LLType will be necessary.

Building:

To fetch use 

    go get 

To build use:

    go test
    go install

then import
