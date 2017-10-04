PADME Skeleton Implementation Plan

Kamil Pawlowski

# Goal

Put together enough to let people start working on the problem and hacking on code.

# Bits Necessary

1. Policy Design

2. API design for each component

3. Skeletal design for each component

4. Skeletal impl for each component

5. Demo Use Case(s) to build skeleton around

6. Review of use cases vs skeletal designs

# Details

## Policy Design

We need a skeletal policy design.  It must include the major features: but especially target and any temporal elements.  Other things can be left till later.

## API Design

We need to sketch out basic function calls for each API interface supporting the use cases. This means the interfaces between Administration and Controller, Controller and Enforcer etc.

## Skeletal Design for Each Component

We need skeletal breakouts for each subcomponent, and the relevant internal interfaces that are going to support this.

## Skeletal Impl for Each Component

We need rough main code path impls for each component

## Demo Use Cases

We need a few real world use cases that we are going to use to validate design decisions against.  These will help us drive the development and achieve a practical MVP.

## Review

We need to review our skeletal impl and use cases against our original designs and docs.

## Discussion/Order

Policy and API design must be done before either of the skeletal steps.  Demo Use Case discovery can be done in parallel, but at least one should be ready before Skeletal Designs.  Component Skeletals can be done in any order (per component) but obviously Design must come before impl. Review should be done last, but may be used as an interim checkpoint as well.  A final review has to be done, even if mini reviews have been done.

