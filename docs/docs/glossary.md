# Glossary
Understanding Tessera and its advanced secret management system requires familiarity with several technical terms. This glossary aims to clarify these concepts for users of all technical levels. Please suggest any changes or additions.


## Attribute
A characteristic or qualification assigned to a user that determines their access rights. Examples include role, department, security clearance level, or project assignment. In Tessera, attributes are used to control access to secrets.

## Attribute-Based Encryption (ABE)
A type of public-key encryption where secrets are encrypted using a set of attributes. Access to decrypt is granted based on matching attributes. ABE allows for fine-grained access control in secret management systems.

## Authority
An authority is an entity responsible for managing and issuing a specific set of attributes. Multiple authorities can coexist in a system, each managing different attribute domains.

## Multi-Authority ABE (MA-ABE)
An advanced form of ABE where multiple independent authorities manage different sets of attributes. This allows for more complex and decentralized access control, which is central to Tessera's design.

## Policy
In Tessera, a policy is a set of rules defining which combination of attributes is required to access a particular secret. Policies are composed of a set of binary operations on attributes. These operations typically include AND, OR, allowing for complex logical combinations. For example, a policy might be expressed as ("Developer" AND "ProjectA") OR "SecurityLevel3", meaning the secret can be accessed by someone who is both a Developer on ProjectA, or by anyone with Security Level 3 clearance.

## Secret Engine
A component in Tessera that manages a specific type of secret or integrates with a particular system for secret management. Different secret engines can handle various types of secrets or external systems.

## Zero-Trust Security
A security model that requires verification for every access attempt, regardless of the user's location or previous authentications. Tessera's attribute-based approach aligns well with zero-trust principles.
