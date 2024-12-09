import Heading from "@theme/Heading";
import styles from "./styles.module.css";

type FeatureItem = {
  title: string;
  description: JSX.Element;
  icon: string;
};

const FeatureList: FeatureItem[] = [
  {
    title: "Robust Attribute-Based Encryption",
    description: (
      <>
        Nebula offers powerful encryption using Attribute-Based Encryption
        (ABE), ensuring secure data protection.
      </>
    ),
    icon: "🔐",
  },
  {
    title: "Policy-Based Access Control",
    description: (
      <>
        Nebula applies Reader and Writer Policies to ciphertexts, granting
        access only to users with attributes that satisfy the policies.
      </>
    ),
    icon: "📝",
  },
  {
    title: "Secure User Key Management",
    description: (
      <>
        Access is granted only to users possessing user keys with attributes
        that meet the policies, enhancing security.
      </>
    ),
    icon: "📝",
  },
];

function Feature({ title, icon, description }: FeatureItem) {
  return (
    <div className={styles.featureCard}>
      <div className="icon">{icon}</div>
      <Heading as="h3">{title}</Heading>
      <p>{description}</p>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <div className="container">
      <section className={styles.features}>
        <Heading as="h2" className={styles.keyFeatures}>
          Key Features
        </Heading>
        <div className={styles.featureGrid}>
          {FeatureList.map((props, idx) => (
            <Feature key={idx.toString()} {...props} />
          ))}
        </div>
      </section>
    </div>
  );
}
