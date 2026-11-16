# Security policy

Doriath is pre-alpha and has one maintainer. Nobody has audited its code.

## Report a problem

Report a problem privately with [GitHub private vulnerability reporting](https://github.com/fnune/doriath/security/advisories/new). Do not open a public issue for it. The maintainer answers when time allows, and cannot promise a date for a fix.

## Scope

These problems are in scope:

- An escape from the jail, such as reaching a file, socket or process that the profile does not show.
- A bypass of a rule, such as a request that the proxy allows although a rule holds or denies it.
- A leak of a token through the proxy, to the agent, the logs or a host that the credential is not for.

Limits that the project already knows are in the [Limits section of the threat model](https://doriath.fnune.com/threat-model/#limits). A report about one of them is not a new finding, unless it shows that a limit is wider than the page says.
