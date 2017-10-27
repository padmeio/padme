PADME Policy Definition

Kamil Pawlowski

# Introduction

The following is a first cut at a possible format for PADME policies.  The expects to end up as some kind of YAML or Protobuf style format.  For deployment purposes that translates to binary may be valuable.  This is not quite in BNF form, but will end up there eventually.

# Definition and Discussion

Before defining a policy, a pair of subcomponents must first be defined: resource and duration.

Recall that a resource identifies both the caller and callee in PADME.

## Resource

### Resource := address, identified_by

<table>
  <tr>
    <td>address</td>
    <td>string/uri - a uri which identifies the particular resource affected by this policy.

The format here is TBD, however it must support:
Different kinds of resources (i.e. network ports as well as http endpoints, for example)
Some amount of widlcarding (i.e. a http endpoint on one machine or the whole zone)</td>
  </tr>
  <tr>
    <td>identified_by</td>
    <td>(TBD) either a certificate, token, or name which must be provided in/b the request when asking for access to the resource.

Examples:
a request is signed by a certificate listed in the identified field, which is verified before the request is processed
a request presents a token (from oauth, kerberos, etc) that is verified
a request comes from a specific source ip or named host, this source is verified before the request is processed</td>
  </tr>
  <tr>
    <td>rate</td>
    <td>Max RPS this resource is permitted to handle.  This may be measured locally or on aggregate remotely.  That is left as an implementation detail. However any implementation must describe the time bound for rate measurement feedback.</td>
  </tr>
</table>


### Digression on Identified_By

Identified is an open ended field, allowing a bring ‘your own’ functionality, beyond those presently conceived by the authors. A company might wish to tie their legacy RADIUS (NOTE:  https://en.wikipedia.org/wiki/RADIUS) into their PADME architecture.  As such Identified_By is broken down further with one mandatory field (type) and all other fields being optional/defined by the specific implementation.  PADME by default ships with a set of identity types (TBD). The type field is a unique string, with globally available values administered through PADME. The assignment and management of local one offs within a zone is TBD. 

## Duration

### Duration := start, end

<table>
  <tr>
    <td>start</td>
    <td>UTC time</td>
  </tr>
  <tr>
    <td>end</td>
    <td>UCT time</td>
  </tr>
</table>


Now one can define a Policy

## Policy

### Policy := version, uuid, description, target, allowed, disallowed, timeline, subpolicies, signature

<table>
  <tr>
    <td>version</td>
    <td>long - the policy format version</td>
  </tr>
  <tr>
    <td>uuid</td>
    <td>string - A globally unique id for this policy. ‘Globally’ here means within the same zone.  Copying policies between zones results in different uuids. </td>
  </tr>
  <tr>
    <td>description</td>
    <td>string - a human readable string for admin purposes </td>
  </tr>
  <tr>
    <td>target</td>
    <td>Resource - the resource controlled by this policy. The identity of the resource must be verified before the policy goes into effect.</td>
  </tr>
  <tr>
    <td>allowed</td>
    <td>list<Resource> - a list of resources that have been explicitly granted access to the resource. This may be empty. If allowed and disallowed are not empty, disallowed wins if there is a conflict.</td>
  </tr>
  <tr>
    <td>disallowed</td>
    <td>List <Resource> - a list of resources that have been explicitly denied access to the resource. This may be empty. If allowed and disallowed are not empty disallowed wins if there is a conflict</td>
  </tr>
  <tr>
    <td>timeline</td>
    <td>Duration - describes when the policy being being enforced and when it stops being enforced.</td>
  </tr>
  <tr>
    <td>subpolicies</td>
    <td>List<Policy> a list of policies that comprise this policy. This may be empty. (see below).</td>
  </tr>
  <tr>
    <td>signature</td>
    <td>String - each policy is signed. This is the signature of the policy. It covers all fields except itself.  If sub policies are present they are covered by this signature. This must be verified before the policy goes into effect.</td>
  </tr>
</table>


# Composition Of Policies

When subpolicies are present, policy evaluation uses the least permissive interpretation in the policy stack.  I.E. Parent and child are evaluated, that the result used is that which gives the least permission.  This happens recursively.  For example:

* If the parent policy allows access to all hosts on port:80 and the child policy only allows access to a specific host on port:80, then only that host will be allowed under the parent policy.

* If the child policy is valid for the next two weeks, while the parent policy is only valid for the next two hours, then the result of the parent policy will be that it is only valid for the next two hours.

    etc.

        

