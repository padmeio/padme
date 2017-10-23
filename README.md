PADME Overview

Authors: *Jeyappragash JJ, Kamil Pawlowski, Manish Mehta*

Version 0.1

# Introduction

This is a working skeleton for driving work on the PADME spec.  This document presently consists of three sections: Problem Statement, Design Goals, and Skeletal Solution.   The Problem Statement defines the problem we are trying to address.  The Design Goals constrain the problem.  The Skeletal Solution contains an initial design.

# Problem Statement

PADME streamlines configuration of access policies up and down the stack in a heterogeneous (cloud) environment.

## Elaboration

PADME aims to address two sources of complexity for access policies: heterogeneity, and temporality. 

## Heterogeneity

Every component (switch, router, load balancer, operating system, web server, etc) has its own configuration mechanism and language.  Similarly each cloud provider has different ways to configure each of these functions.  An entity that makes use of many different components and or clouds must configure access policies in each of them differently.  This is slow, tedious (sometimes manual) and error prone.  PADME aims to obviate these problems by providing a unified framework for defining access control policies. Plugins are used to apply these to specific components.

## Temporality

In a modern context services (resources) come and go constantly.  This happens because of service deployment or depreciation. It also happen (or appears to happen) because of network partitions, propagation delays, or the general consequences of the CAP theorem (NOTE:  https://en.wikipedia.org/wiki/CAP_theorem).  Current approaches tend to grant or revoke permissions permanently and require human intervention to perform this action.  Further they do not deal with network partitions in a well understood way.  PADME provides explicit temporal semantics for access policies, and an explicit intelligible approach to the implications of the CAP theorem. 

# Design Goals

What follows are the design goals we would like to meet, and the features we would like to support. In each case this is (presently) an unordered list

## Goals

* Provable, Composable Security

* Simplicity (Ease of Use)

* Defined/well understood behavior in a distributed environment (i.e. understanding the CAP theorem)

## Features

* Supports full lifecycle for policies, from definition, distribution, evaluation, enforcement and verification

* Support for transient policies (i.e. users/resources that come and go)

* Support for variable levels of enforcement (or some amount of play/slop) to reduce overhead on requests and support distributed cases

* Support for policy life cycle (versions & version tracking)

* Support for request costs/budgets

* Plugin architecture to allow control of arbitrary underlying components

* Provable security that can be verified off line

* Support for bootstrap permissions

* Support for federated identities

* Auditable

* Compliance friendly

* Explicit semantics for permission hierarchies 

* Clear Permission Delegation Model

* Compatibility with RBAC systems

* Support for atomicity of multiple operations.

# Skeletal Design

Here a very modest design is proposed.

There are three fundamental concepts in this design: resource, operation, and policy.   

A resource is simply a thing to which access must be controlled.  A resource is, for example a specific web page,  an IP address, a domain, a service etc.   A resource is identified by a URI.  The format of this URI is TBD.

An operation is something that can be performed on this resource.  The fundamental operations permitted on a resource are READ and WRITE.  (As an example, when translated to HTTP,  write might subsume PUT, POST, and DELETE.)

A policy states that one resource (source) has the permission to perform an operation on a second resource (target).  Policies are composable. I.E. it is possible to build a larger policy out of smaller individual policies.

The right to create, modify or remove a policy for a resource is granted by being allowed to perform the WRITE operation on a URI that can be considered a root (higher level scope) than the resource in question.

#Padme and OPA

PADME defines a system that provides full lifecycle policy management and enforcement. OPA focuses on a policy definition language and its attendant execution.  PADME addresses definition, distribution, execution, and enforcement of policies in both legacy systems and modern architectures, with specific emphasis on issues arising from the CAP constraints. To enable this PADME provides a lightweight interface for centrally defining policies across disparate resources. Pluggable enforcers specific to each resource do policy enforcement.  PADME can leverage OPA where infrastructures are OPA enabled.

# Conclusion

The above sketches out the rough approach being taken with respect to PADME.

