Padme Use Cases

Author: Kamil Pawlowski

# Introduction

This describes the core use cases that must be supported by PADME. 

# Core Concepts

A number of concepts are used throughout this document.  The concepts of Resource, Operation and Policy are inherited here from the Padme Overview (NOTE:  Padme Overview).  The core concepts are expanded to also include an Administrator, a Zone, a Controller and an Enforcer.

An Enforcer is a PADME component that checks policies.  Specifically, it determines if a policy exists that determines if one resource (the source) is allowed to perform a given operation on another (the target).  Further it determines if under that policy the operation is permitted. 

A Controller is a PADME component that enables policy management. Specifically, it distributes policies to enforcers, and removes them from enforcers.

A Zone is grouping of controllers and the enforcers they control.  Controllers in that zone share control of the enforcers with in it.  It is a logical, rather than physical PADME component.  A hierarchy of zones is possible in PADME, however its is beyond the scope of this document.

An Administrator is an end user (human or machine) that defines or removes policies.  Policies are added or removed via one or more controllers.

# Policy Life Cycle

Under PADME Policies go through the following life cycle stages: Definition, Distribution, Execution, Enforcement and Verification.   

Policies are defined by Administrators.  Here the details of a policy are defined.  A new Policy may simply be the composition of existing Policies.

Policies are distributed by Controllers to Enforcers. Distribution provides bounds for CAP theorem Issues. 

Policies are executed and enforced by Enforcers.  The act of an Enforcer adding a policy to its active list of enforced policies is its execution.  Enforcement occurs when the policy is used, along with others, to determine if a request should be accepted to rejected.

Policies are verified by Administrators. This occurs in the testing of policies, the view of distribution results, and the auditing of traffic passed through the system as a whole. 

# Use Cases

## Policy Use Cases

1. A policy must identify a source that is initiating the request.  This maybe a wildcard/glob/etc.

2. A policy must identify a target to which access is being requested.  This maybe a wildcard/glob/etc.

3. Identification of a source or target must be sufficiently generic that they can support everything from web server (URLs) to switches.

4. A policy must identify which operations the source would like to make on the target. This maybe a wildcard/glob/etc.

5. A policy must define the time period (window) during which it is valid.

6. A policy must define its relative order of application with respect to other policies. E.g. Policy B, is applied after Policy A but before C.

7. A policy must be tamper proof.

8. A policy must be composable with other policies to define a larger policy for intelligibility and management reasons

## Enforcer Use Cases

1. An enforcer defaults to fail closed. I.E. Any request that is not explicitly permitted by a policy is denied.

2. An enforcer must render a yes or no decision on a given request.

3. An enforcer must render a verdict on a request within 2ms (NOTE:  This should be low enough overhead for machine to machine communications with in a DC, with minimal application impact.).

4. An enforcer must verify the integrity of a policy (rejecting it if it is invalid)

5. An enforcer must enforce the window during which a policy is active

6. An enforcer must respect the relative order of policies

7. An enforcer must not disable contradictory policies (NOTE:  This is the administrator shooting themselves.)

8. An enforcer must continue to function even if it cannot talk to any controller

9. An enforcer must report what policies it presently has configured, as well as their present state.

10. An enforcer must report when a policy becomes active or inactive

11. An enforcer must report statistics regarding the number of requests accepted or rejected

## Controller Use Cases

1. A controller must allow a new policy to be defined

2. A controller must allow an existing policy to be edited

3. A controller must allow an existing policy to be deleted

4. A controller must become aware of new enforcers

    1. An enforcer must be able to register itself with a controller

    2. A controller must be able to be explicitly told of an enforcer

5. A controller must become aware of existing enforcers being lost (going away)

6. A controller must distribute policies to some number of enforcers it knows about

7. A controller must co-exist with other controllers in the same zone who share ownership of the same set of policies and enforcers

    3. A controller must co-exist with other controllers who share ownership, even if those controllers are not reachable

8. A controller must deliver only policies relevant to any given enforcer to that enforcer (e.g. policies for a switch are not delivered to a web server)

9. A controller must support composable policies

10. A controller must render policies so that they can be verified by an enforcer

11. A controller must report  the present state of policy deployment.

12. A controller must report when a policy has been distributed to all enforcers it shares ownership of.

13. A controller must share operations on policies that it is mediating to other controllers.

## Zone Use Cases

1. It must be possible to add enforcers to a zone

2. It must be possible to remove enforcers from a zone

3. It must be possible to add or remove enforcers even when they are not reachable

4. It may be possible to auto discovery enforcers within a zone

5. It must be possible to add controllers to a zone

6. It must be possible to remove controllers from a zone

7. It must be possible to add or remove controllers even when they are not reachable

8. It may be possible to auto discover controllers within a zone

9. It must be possible to create a zone with no enforcers or controllers in it

10. All controllers in the same zone must share the same policies

11. A controller must belong to only one zone

12. An enforcer must belong to only one zone

## Administrator Use Cases

All Administrator Use Cases implicitly apply to a specific zone. 

1. An administrator must be able to add a policy

2. An administrator must be able to remove a policy

3. An administrator must be able to edit a policy

4. An administrator must be able to preview the complete system policy state before making a change

5. An administrator must be able to test a request against a potential new policy state

6. An administrator must be able to see what policies are active in the system

7. An administrator must be able to audit what policies are in effect and were in effect in the past

8. An administrator must be aware of a partition in the network that can prevent a policy operation from occurring

9. An administrator must be able to verify that a policy was distributed to enforcers, and specifically to which enforcers

10. An administrator must see any errors encountered in distribution of policies

11. An administrator must see stats pertaining to the number of requests accepted and rejected by each policy

12. An administrator must be able to audit the behavior of specific requests at a given enforcer

13. An administrator must be able to measure latency added to any given request by applying policies in the enforcer

