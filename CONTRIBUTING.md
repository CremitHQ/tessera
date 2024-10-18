## Contribution Guidelines

Thank you for your interest in contributing to Tessera! We appreciate your efforts to help us enhance and refine our open-source secret management platform. This guide provides instructions and best practices to streamline your contribution process.

---
### Getting Started

#### 1. Fork the Repository

Begin by forking the Tessera repository to your own GitHub account. This creates a personal copy where you can make changes independently.

#### 2. Clone Your Fork Locally

Clone the forked repository to your local development environment:

```sh
git clone https://github.com/your-username/tessera.git
```

Replace your-username with your GitHub username.

#### 3. Set Upstream Repository

To keep your fork synchronized with the original repository, add it as an upstream remote:

```sh
cd tessera
git remote add upstream https://github.com/CremitHQ/tessera.git
```

#### 4. Create a New Branch

Always create a new branch for your work to isolate your changes:

```sh
git checkout -b feature/your-feature-name
```

Use a descriptive branch name that reflects the purpose of your changes.

--- 
### Making Changes

#### 1. Implement Your Changes

Make the necessary code changes or additions in your branch. Ensure you follow the project’s coding standards and conventions.

#### 2. Write Tests

Include unit or integration tests for your changes where applicable. This helps maintain code quality and prevents regressions.

#### 3. Update Documentation

Update or add inline documentation and comments to explain your code. If you modify existing features or add new ones, update the relevant documentation accordingly.

---
### Committing Your Changes

#### 1. Commit with Clear Messages

Write clear and descriptive commit messages:

```sh
git commit -m "feat(project-name): Add support for multi-factor authentication"
```
Each commit should represent a logical set of changes.

#### 2. Push to Your Fork

Push your branch to your forked repository on GitHub:
```sh
git push origin feature/your-feature-name
```

---
### Code Review Process

- Review Timeframe: We aim to review pull requests promptly but ask for your patience during busy periods.
- Feedback: Be prepared to make revisions based on feedback. Our goal is collaborative improvement.
- Approval: Once approved, your changes will be merged into the main branch.


---
### Additional Guidelines

#### Coding Standards
- Follow the project’s coding style and conventions.
- Write clean, readable, and maintainable code.
- Avoid introducing unnecessary dependencies.

#### Communication
- Issues: For bugs or feature requests, open an issue before submitting a PR.
- Discussions: Use GitHub Discussions or the project’s communication channels for questions or proposals.

#### Respect and Professionalism
- Be respectful and considerate in all interactions.
- Provide constructive feedback and welcome it in return.
- Acknowledge and credit the work of others.

#### Reporting Issues

If you find a bug or have a suggestion:
1.  Search Existing Issues: To avoid duplicates, check if an issue already exists.
2. 	Open a New Issue: If none exists, create a new issue with a clear and descriptive title.
3.  Provide Details: Include steps to reproduce, expected behavior, and any relevant logs or screenshots.

#### License

By contributing to Tessera, you agree that your contributions will be licensed under the [Apache License 2.0.](./LICENSE)

--- 
Once again, We greatly appreciate your contributions and efforts to improve Tessera. Together, we can build a more secure and versatile secret management solution for everyone.