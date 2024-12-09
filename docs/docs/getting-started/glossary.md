# Glossary

Understanding Nebula and its advanced secret management system requires familiarity with several technical terms. This glossary aims to clarify these concepts for users of all technical levels. Please suggest any changes or additions.

## Attribute
A characteristic or qualification assigned to a user that determines their access rights. Examples include role, department, security clearance level, or project assignment. In Nebula, attributes are used to control access to secrets.

## Attribute-Based Encryption (ABE)
A type of public-key encryption where secrets are encrypted using a set of attributes. Access to decrypt is granted based on matching attributes. ABE allows for fine-grained access control in secret management systems.

## Authority
An entity responsible for managing and issuing a specific set of attributes. Multiple authorities can coexist in a system, each managing different attribute domains. In Nebula, authorities issue user keys based on the attributes a user possesses and expose the public keys used for encryption.

## Machine Identity
A unique identifier assigned to machines or services within Nebula. It ensures that only authorized machines can access certain secrets and interact with the Nebula system. Machine identities are managed by the **Authorization** server.

## Multi-Authority ABE (MA-ABE)
An advanced form of ABE where multiple independent authorities manage different sets of attributes. This allows for more complex and decentralized access control, which is central to Nebula's design.

## Policy
In Nebula, a policy is a set of rules defining which combination of attributes is required to access a particular secret. Policies are composed of a set of binary operations on attributes. These operations typically include AND, OR, allowing for complex logical combinations. For example, a policy might be expressed as `("Developer" AND "ProjectA") OR "SecurityLevel3"`, meaning the secret can be accessed by someone who is both a Developer on ProjectA, or by anyone with Security Level 3 clearance.

## Public Key
A cryptographic key used in Nebula for encrypting secrets. Public keys are exposed by authorities and are used in the encryption process to ensure that only users with the corresponding user keys can decrypt the secrets. Public keys are integral to the ABE process, enabling secure and attribute-based encryption.

## Secret Engine
A component in Nebula that manages a specific type of secret or integrates with a particular system for secret management. Nebula incorporates functionalities such as secret rotation and SSH secret engines, similar to those offered by Vault. These features are managed through separate agents, allowing for automated and secure handling of secrets without introducing additional complexity to the core system. Different secret engines can handle various types of secrets or external systems, providing flexibility and extensibility to meet diverse secret management needs.

## User Key
A secret key assigned to a user, generated based on the attributes the user possesses. This key is unique to the user and is used exclusively for decrypting secrets that match the user's attributes. User keys are issued by authorities and are essential for maintaining secure access to encrypted secrets.

## Backbone Server
The core component of Nebula responsible for storing data and managing global parameters used in ABE. The backbone server acts as the central repository for encrypted secrets and oversees the overall data integrity and consistency across the Nebula system.

## Authorization Server
A critical component in Nebula that handles user identification and authentication through various identity providers (IdPs) and authentication protocols such as SAML and OIDC. The authorization server issues JSON Web Tokens (JWTs) upon successful authentication and manages machine identities to ensure that only authorized entities can interact with the system.

## Nebula Components Overview

1. **Backbone Server**
   - **Function**: Stores encrypted secrets and manages global parameters required for ABE.
   - **Role**: Acts as the primary data repository ensuring data integrity and consistency.

2. **Authorization Server**
   - **Function**: Identifies and authenticates users via external IdPs and various authentication methods like SAML and OIDC.
   - **Role**: Issues JWTs for authenticated users and manages machine identities to secure interactions within Nebula.

3. **Authority Server**
   - **Function**: Issues user keys based on user attributes and exposes public keys used for encryption.
   - **Role**: Manages the distribution of user-specific keys and ensures that public keys are available for secure encryption processes.

## Additional Terms

### End-to-End Encryption (E2EE)
A security mechanism in Nebula that ensures data is encrypted on the sender's side and only decrypted by the intended recipient. E2EE protects data from interception or unauthorized access during transmission and storage.

### JSON Web Token (JWT)
A compact, URL-safe means of representing claims to be transferred between two parties. In Nebula, JWTs are issued by the Authorization Server upon successful user authentication and are used to securely transmit user identity and attribute information.

### Identity Provider (IdP)
An external service that authenticates users and provides identity information to Nebula. Nebula's Authorization Server integrates with various IdPs using protocols like SAML and OIDC to facilitate seamless user authentication and authorization.

### Auditable System
Nebula is designed to be auditable, providing comprehensive logging and monitoring capabilities. This ensures that all access and modifications to secrets can be tracked and reviewed, enhancing security and compliance with regulatory requirements.
