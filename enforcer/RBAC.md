# Representing RBAC in PADME #

Copyright Kamil Pawlowski 2018

# Introduction #

This document describes how PADME can efficiently represent many 
different Role Based Access Control [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control) 
It also shows how this might be applied to the kubernetes
RBAC implementation.

# Background #

RBAC is a common access control scheme.  Simplistically, in RBAC users are 
assigned roles. Roles have permissions to perform certain operations. Thus
a user is given permission to perform a given operation by the transitive 
relation from user to role to permission. In RBAC a given user may have more
than one role.  RBAC systems are popular because they are intelligible -
it is very clear who can do what and why.

In many cases when an request is tested against an RBAC policy, only
the user is known. An external lookup is done to find the user's groups
and then these are used to find the resources the user is allowed to 
access.

Unfortunately in the core use cases defined by PADME, external lookups are not
possible - they do not work in the context of a partition.  Further they are 
too slow to put into the main line of a web request that may need to traverse 
several layers of infrastructure.  Finally, they do not allow users to reason
about policies as consistent entities over time. 

The challenge for PADME is how to efficiently represent RBAC policies
at the enforcer. Recall that PADME is only interested in determining if a 
request is allowed or not.  PADME is not interested in other capabilities
that may be associated with an RBAC policy.

# What Do Really Need To Know #

Ultimately PADME is purely interested in the following question:

    Is user allowed to access resource?

This suggests that if RBAC policies are flattened and only contain the final
user resource mapping (i.e. a given user is allowed to access the following 
resources), then the enforcer could give an up/down decision on the 
acceptability of the request. 

However this results in a combinatorial explosion.  The degenerate case
is that if there are u users who can belong to g groups which control 
r resources, then there might be as many as:

    u * g * r

policies (or rules) that must be generated in this flattening. (As an 
aside, the approach described here works equally well if there are kinds
or other indirection in this pattern).

Thus a compressed structure for these rules is required, if a flattening
approach is to work.

# You Probably Have Permission or You Definitely Don't #

[Bloom Filters and Cuckoo Filters](https://bdupras.github.io/filter-tutorial/) are 
probabilistic data structures that efficiently represent wide ranges of values.
They are used to determine set membership. False positives are possible, but false
negatives are not.  So you either don't have permission or you probably do. They
operate in constant time from the pov of PADME.  The question then becomes is it 
possible to tune these structures so that they are usable in the PADME context?

For the purpose of the remainder of this discussion we assume the use of 
Cuckoo Filters as they are O(1) lookup, and provide better characteristics 
for controllers to work with. They have the same basic 'maybe or no' characteristics
as bloom filters.

A cuckoo filter (bucket size of 4) for u * g * r = 10000, with an false positive rate 1E-24,
requires < 900K Bytes of storage.  At 1 Billion Requests/Second 3.17E+07 years before an
error occurs. The space requirements grow linearly with u * g * r (100K < 9M Bytes).  
However 900K especially at modern DC data rates is very small. 

Clearly such an approach will struggle if every node is a user and every request is 
for a different resource.  However, such schemes are not particularly accessible to
human beings, and as such are unlikely to come up in the wild at present.  If they do, 
a different approach is required.  

Where u * g * r is larger than 10000, then it makes sense to use multiple policies.
Each policy should then use a cuckoo filter with an appropriately absurdly low
false positive probability, to describe which users belong to that police.

The resulting structure provides a fast lookup while reducing the probability of 
a false positive to an abritratily small value.  Further the structure is compact
when considered in the context of mice and elephant flows in a modern data center.

## Wild Cards ##

PADME supports tail matching wild cards. A common pattern in resource rule 
matching is to match patterns such as:

    /foo/*
    /* 

In order to match patterns of this nature, that specific pattern should
be added to to the filter.  When attempting to match a given resource PADME
matches the resource specifically, and then tries all wild card patterns
that this pattern can support.  The most specific match will always be
tried first.

The rules for this are as follows.  

    1 the resource itself is attempted
    2 searching from the back all text before the first / is removed and replaced with a wild card.
    3 a match is attempted using this new URI
    3 steps 2 an 3 are repeated till the URI is empty

Thus for example if we have:

    Policy 1: /foo/bar/sna
    Policy 2: /foo/bar/*
    Policy 3: /foo/san*
    Policy 4: /foo
    Policy 5: /*
    
Requests will match as follows:

    /foo/bar/sna -> matches policy 1
    /foo/bar/sna2 -> matches policy 2
    /foo/bar -> matches policy 5 
    /foo/bar2 -> matches Policy 5
    /foo/ -> matches policy 5
    /foo -> matches policy 4
    /bar/sna -> matches policy 5
    /bar -> matches policy 5

The performance of this algorithm is linear in the number of separators in the path
not in the number of rbac rules.  As a result it should be sufficient for
most application.

With this approach it is possible to include service/path level wildcarding 
in PADME policies while getting the benefit of using a Cuckoo Filter.

## Converting Kubernetes RBAC Into Probalistic PADME Policies ##

It is possible to replace kubernetes RBAC implementation with webhook calling into
a PADME enforcer.  The following describes how kubernetes RBAC can be translated
into the PADME Policy implementation. Recall that kubernetes RBAC contains
only positive rules (i.e. anything not explicitly allowed is forbidden).

The [k8s webhook](https://kubernetes.io/docs/admin/authorization/webhook/)
appears to provide the following information when a call is made:
- resource namespace
- resource verb
- resource group (apiGroup)
- resource name
- username
- user groups

It is not clear, if in the event of a specific resource the 'resourceName' 
appears or not. Thus for the time being specific resourceNames as they appear 
in the rules section of a role are excluded.

[kubernetes RBAC](https://kubernetes.io/docs/admin/authorization/rbac/) 
allows binding roles within a given namespace (RoleBinding) or a cluster-wide 
role (ClusterRoleBinding), the scheme described below can represent either. 

Obviously a custom rule and matcher must be created to support these 
kinds of policies with in PADME.  For simplicity, a separate policy is used 
here for user bindings and group bindings. This is to simplify implementation, 
as user groups are provided by the webhook impementation.  These could be 
excluded by having the complete user to group mapping when the rule
Similarly a separate policies are used for namespaced and cluster wide 
bindings. Again these could be merged, however that would require
defining reserved namespace value that would identify clusterwide mappings.
Thus the output of this process would be four different policies.

- namespace-user
- namespace-group
- clusterwide-user
- clusterwide-group

### Algorithm ###
This alogirthm assumes a knowledge of all RoleBindings, ClusterRoleBindings,
and Roles. Users and groups are are infered from the bindings.  The
following is done for both RoleBindings and the ClusterRoleBindings. It 
is assumed that a RoleBinding will only refer to Role roleRef, and
a ClusterRoleBinding to a ClusterRole roleRef. Similarly it is assumed
that the namespace in the rolebinding and role match.

    foreach RoleBinding, binding
      namespace = binding.namespace
      principle = binding.subjects.name
      role = find_role(binding.roleRef.name)

      foreach role.rules.apiGroup, apiGroup
        foreach role.rules.resources, resource
          foreach role.rules.resources.verbs verb
            if binding.subjets.kind == user
              insert into user policy (namespace, principle, apiGroup, verb, resource)
            else 
              inesrt into group policy (namespace, principle, apiGroup, verb, resource)

The webhook then provides the following inputs and these must be tested untill a success
is returned or all policies are checked.  Depending on the policy username or 
all groupnames are checked.
    foreach name, principle  //name can be username or groupname)
      check if present (namespace, principle, apiGroup, verb, resource)

As an example we have the following from the RBAC examples:

    kind: Role
    apiVersion: rbac.authorization.k8s.io/v1
    metadata:
      namespace: default
      name: pod-reader
    rules:
      apiGroups: [""] # "" indicates the core API group
      resources: ["pods"]
      verbs: ["get", "watch", "list"]

    kind: RoleBinding
      apiVersion: rbac.authorization.k8s.io/v1
    metadata:
      name: read-pods
      namespace: default
    subjects:
      kind: User
      name: jane
      apiGroup: rbac.authorization.k8s.io
    roleRef:
      kind: Role
      name: pod-reader
      apiGroup: rbac.authorization.k8s.io

This would result in the following inserted into the user policy fiter
    
    (default, jane, rbac.authorization.k8s.io, get, pods)
    (default, jane, rbac.authorization.k8s.io, watch, pods)
    (default, jane, rbac.authorization.k8s.io, list, pods)

### Other Applications ###
A similar mechanism could be used for packet based rules, if a packet is first turned into
a string.  However the rules applied by the enforcer to accomplish wild carding
(especially in the CDIR case) must be more extensive.

# Implementing In PADME #

This approach requires a specific RBAC policy matcher to be constructed in policy.go.
A golang [cuckoo filter](https://github.com/seiflotfy/cuckoofilter) implementation
is available.
