import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Robust Attribute-Based Encryption',
    description: (
      <>
        Tessera offers powerful encryption using Attribute-Based Encryption
        (ABE), ensuring secure data protection.
      </>
    ),
  },
  {
    title: 'Policy-Based Access Control',
    description: (
      <>
        Tessera applies Reader and Writer Policies to ciphertexts, granting
        access only to users with attributes that satisfy the policies.
      </>
    ),
  },
  {
    title: 'Secure User Key Management',
    description: (
      <>
        Access is granted only to users possessing user keys with attributes
        that meet the policies, enhancing security.
      </>
    ),
  },
];

function Feature({ title, Svg, description }: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
