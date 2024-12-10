import Link from "@docusaurus/Link";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import HomepageFeatures from "@site/src/components/HomepageFeatures";
import Heading from "@theme/Heading";
import Layout from "@theme/Layout";
import clsx from "clsx";

import styles from "./index.module.css";

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx("main__header", styles.mainHeader)}>
      <Heading as="h1" className={styles.title}>
        {siteConfig.title}
      </Heading>
      <p className={styles.subtitle}>{siteConfig.tagline}</p>
      <div className={styles.buttons}>
        <Link
          className="button button--secondary button--lg"
          to="/docs/getting-started/introduction"
        >
          Read Docs
        </Link>
      </div>
    </header>
  );
}

export default function Home(): JSX.Element {
  return (
    <Layout description="A secret manager offering robust Attribute-Based Encryption (ABE) for secure data protection.">
      <HomepageHeader />
      <main>
        <HomepageFeatures />
      </main>
    </Layout>
  );
}
