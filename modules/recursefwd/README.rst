.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-recursefwd-readme:

Recursive forwarding policy
===========================

The :ref:`policy module <mod-policy>` only evaluates its rules against the
initial query of each request.  The internal sub-queries issued while
resolving it (nameserver addresses, DNSSEC lookups, glue records, ...) keep
using ordinary recursion and are therefore not affected by forwarding rules.

The ``recursefwd`` module closes that gap.  It keeps its own set of policy
rules and re-evaluates them on every produced query, including recursive
sub-queries.  A matching query is switched to forwarding mode and sent to the
configured upstream resolver instead of being resolved recursively.

The module is a pure Lua layer loaded next to the iterator; it does not change
the default configuration and only acts on queries that match an explicit
rule, so existing setups keep working unchanged.

Loading
-------

Load the module after the iterator so that its ``produce`` hook runs once the
iterator has prepared each (sub-)query:

.. code-block:: lua

  modules.load('recursefwd > iterate')

Rules
-----

Forward every query whose QNAME belongs to a subtree (suffix match):

.. code-block:: lua

  recursefwd.suffix('example.com.', '192.0.2.53')

Several upstreams can be given as a list, and the ``address@port`` syntax is
accepted as well:

.. code-block:: lua

  recursefwd.suffix('example.com.', {'192.0.2.53', '2001:db8::53@5353'})

Forward every query independently of its QNAME:

.. code-block:: lua

  local rule = recursefwd.all('192.0.2.53')

Rule handles returned by the functions above can be removed again:

.. code-block:: lua

  recursefwd.del(rule)

Rules already switched to forwarding (by this module or by the policy module)
are never reconfigured, so combining both modules is safe.
