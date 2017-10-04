PADME MVP Proposal

# Introduction

This document defines features that must be present in an Minimal Viable Product for PADME.  The goal of this document is to drive the design of the features mentioned here in.

The features we have identified as critical are:

* Temporally Aware Policies

* Well understood behavior in the face of the CAP theorem (i.e. operation in a distributed environment).

# Features

Basic Requirements

* A policy must allow a Y/N decision on an operation

* A policy must default to deny

* A policy must be composable

Performance Requirements

* Checking a policy (a single rule) for a Y/N answer must take < (?) ms (NOTE:  http://highscalability.com/blog/2013/1/15/more-numbers-every-awesome-programmer-must-know.html
It is not clear what the number should be here, it must be a small relative to the in DC network round trip plus service processing time of an interservice call.)

Temporally Aware Policies

* Time is a first class citizen in a policy

    * A policy is only valid for a defined period of time

CAP Theorem

* A well defined, easily understood/verifiable behavior must be defined for each of these cases

    * Consistency: PADME is aware and handles propagation delay in policies, replication delay, and individual node failures

    * Availability: PADME is aware and handles cases where individual nodes that are sources of truth for policies as well as other components may fail or be unavailable

    * Partition: PADME components (especially policy enforcement) operate correctly (though possibly in a degraded fashion) when unable to communicate with sources of truth for ‘extended’ periods of time.

