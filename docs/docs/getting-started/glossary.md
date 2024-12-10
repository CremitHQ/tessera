# Glossary

Understanding Nebula and its advanced secret management system requires familiarity with several technical terms. This glossary is designed to clarify these concepts for users of all technical levels. Please suggest any changes or additions.

## Attribute
A characteristic or qualification assigned to a user that determines their access rights. Examples include role, department, security clearance level, or project assignment. In Nebula, attributes are fundamental to controlling access to secrets and enforcing policies.

## Attribute-Based Encryption (ABE)
A type of public-key encryption where secrets are encrypted using a set of attributes. Access to decrypt is granted to users or machines whose attributes whose attributes match the encryption policy. ABE allows for fine-grained access control in secret management systems.

## Authority
An entity responsible for managing and issuing specific sets of attributes. Multiple authorities can coexist in a system, each managing different attribute domains. In Nebula, authorities issue user keys based on the attributes a user possesses and expose the public keys used for encryption.

## Machine Identity
A unique identifier assigned to machines or services within Nebula. It ensures that only authorized machines can access certain secrets and interact with the system. Machine identities are managed by the **Authorization** server.

## Multi-Authority ABE (MA-ABE)
An advanced form of ABE where multiple independent authorities manage different sets of attributes. This enables complex and decentralized access control, critical to Nebula's flexible design.

## Policy
In Nebula, a policy is a set of rules defining which combination of attributes is required to access a particular secret. Policies are composed of a set of binary operations on attributes. These operations typically include AND, OR, allowing for complex logical combinations. For example, a policy might be expressed as `("Developer" AND "ProjectA") OR "SecurityLevel3"`, meaning the secret can be accessed by someone who is both a Developer on ProjectA, or by anyone with Security Level 3 clearance.

## Public Key
A cryptographic key used in Nebula for encrypting secrets. Public keys are securely distributed by authorities and used in the encryption process to ensure that only users with the corresponding user keys can decrypt a secret. Public keys are integral to the ABE process, enabling secure and attribute-based encryption.

## Secret Engine
A modular component in Nebula that handles specific categories of secrets, such as API keys, database credentials, or SSH keys. Secret engines also support automated processes like secret rotation, ensuring security without additional user effort. Nebula's secret engines are extensible and can integrate with external systems to meet diverse secret management needs.

## User Key
A private key unique to each user, generated based on their attributes. This key is issued by the Authority Server and is used exclusively to decrypt secrets matching the user’s attributes. User keys are a critical component of maintaining secure, attribute-based access control.

## Backbone Server
The core component of Nebula responsible for storing data and managing global parameters required in ABE. It acts as the central repository for encrypted secrets and oversees overall data integrity and consistency across Nebula.

## Authorization Server
A critical component in Nebula that handles user identification and authentication through various identity providers (IdPs) and authentication protocols such as SAML and OIDC. The authorization server issues JSON Web Tokens (JWTs) upon successful authentication and manages machine identities to ensure that only authorized entities can interact with the system.



## Additional Terms

### End-to-End Encryption (E2EE)
A security mechanism that ensures data is encrypted on the sender's side and only decrypted by the intended recipient. E2EE protects data from interception or unauthorized access during transmission and storage.

### JSON Web Token (JWT)
A compact, URL-safe means of representing claims to be transferred between two parties. In Nebula, JWTs are issued by the Authorization Server upon successful user authentication and are used to securely transmit user identity and attribute information.

### Identity Provider (IdP)
An external service that authenticates users and provides identity information to Nebula. Nebula's Authorization Server integrates with various IdPs using protocols like SAML and OIDC to facilitate seamless user authentication and authorization.

### Auditable System
This comprehensive logging and monitoring capabilities. This ensures that all access and modifications to secrets can be tracked and reviewed, enhancing security and compliance with regulatory requirements.
