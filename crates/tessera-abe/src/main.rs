use rand::Rng as _;
use rand::RngCore as _;
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Instant;
use tessera_abe::utils::secret_shares::remove_index;

use tessera_abe::error::ABEError;
use tessera_abe::utils::aes::decrypt_symmetric;
use tessera_abe::utils::aes::encrypt_symmetric;
use tessera_abe::utils::secret_shares::calc_coefficients;
use tessera_abe::utils::secret_shares::calc_pruned;
use tessera_abe::utils::secret_shares::gen_shares_policy;
use tessera_abe::utils::tools::traverse_policy;
use tessera_miracl::bls48556::big::BIG;
use tessera_miracl::bls48556::big::MODBYTES;
use tessera_miracl::bls48556::big::NLEN;
use tessera_miracl::bls48556::ecp::ECP;
use tessera_miracl::bls48556::ecp8::ECP8;
use tessera_miracl::bls48556::fp48::FP48;
use tessera_miracl::bls48556::pair8;
use tessera_miracl::bls48556::rom::CURVE_ORDER;

use tessera_miracl::hash256::HASH256;
use tessera_miracl::rand::RAND;
use tessera_policy::pest::parse;
use tessera_policy::pest::PolicyLanguage;

pub struct GlobalParams {
    pub g1: ECP,  // G1
    pub g2: ECP8, // G2
    pub e: FP48,  // e(G1, G2) pairing
}

impl GlobalParams {
    pub fn new(mut rng: &mut RAND) -> Self {
        let x = BIG::random(&mut rng);
        let q1 = ECP::generator();
        let g1 = pair8::g1mul(&q1, &x);

        let x = BIG::random(&mut rng);
        let q2 = ECP8::generator();
        let g2 = pair8::g2mul(&q2, &x);

        let e = pair8::fexp(&pair8::ate(&g2, &g1));

        Self { g1, g2, e }
    }
}

pub struct AuthorityKeyPair<'a> {
    pub name: Cow<'a, str>,
    pub pk: AuthorityPublicKey,
    pub mk: AuthorityMasterKey,
}

impl<'a> AuthorityKeyPair<'a> {
    pub fn new<S>(mut rng: &mut RAND, gp: &GlobalParams, name: S) -> AuthorityKeyPair<'a>
    where
        S: Into<Cow<'a, str>>,
    {
        let alpha = BIG::random(&mut rng);
        let y = BIG::random(&mut rng);
        let e_alpha = pair8::gtpow(&gp.e, &alpha);
        let gy = pair8::g1mul(&gp.g1, &y);

        let pk = AuthorityPublicKey { e_alpha, gy };
        let mk = AuthorityMasterKey { alpha, y };
        Self { name: name.into(), pk, mk }
    }
}

pub struct AuthorityPublicKey {
    pub e_alpha: FP48,
    pub gy: ECP,
}

pub struct AuthorityMasterKey {
    pub alpha: BIG,
    pub y: BIG,
}

pub struct UserAttributeKey {
    pub k: ECP8,
    pub kp: ECP,
}

pub struct UserSecretKey {
    gid: String,
    inner: HashMap<String, UserAttributeKey>,
}

impl UserAttributeKey {
    pub fn new<T: AsRef<str>>(
        mut rng: &mut RAND,
        gp: &GlobalParams,
        mk: &AuthorityMasterKey,
        gid: &str,
        attribute: T,
    ) -> Self {
        let t = BIG::random(&mut rng);

        let mut k = pair8::g2mul(&gp.g2, &mk.alpha);
        k.add(&pair8::g2mul(&hash_to_g2(gid), &mk.y));
        k.add(&pair8::g2mul(&hash_to_g2(attribute.as_ref()), &t));

        let kp = pair8::g1mul(&gp.g1, &t);
        Self { k, kp }
    }
}

impl UserSecretKey {
    pub fn new<T: AsRef<str>>(
        mut rng: &mut RAND,
        gp: &GlobalParams,
        mk: &AuthorityMasterKey,
        gid: &str,
        attributes: &[T],
    ) -> Self {
        let inner = attributes
            .iter()
            .map(|attr| {
                let key = UserAttributeKey::new(&mut rng, gp, mk, gid, attr);
                (attr.as_ref().to_string(), key)
            })
            .collect();
        Self { gid: gid.to_string(), inner }
    }

    pub fn add_attribute<T>(&mut self, mut rng: &mut RAND, gp: &GlobalParams, mk: &AuthorityMasterKey, attribute: T)
    where
        T: AsRef<str> + Clone,
    {
        let key = UserAttributeKey::new(&mut rng, gp, mk, &self.gid, attribute.clone());
        self.inner.insert(attribute.as_ref().to_string(), key);
    }

    pub fn add_attributes<T>(
        &mut self,
        mut rng: &mut RAND,
        gp: &GlobalParams,
        mk: &AuthorityMasterKey,
        attributes: &[T],
    ) where
        T: AsRef<str> + Clone,
    {
        for attr in attributes {
            let key = UserAttributeKey::new(&mut rng, gp, mk, &self.gid, attr);
            self.inner.insert(attr.as_ref().to_string(), key);
        }
    }
}

struct Ciphertext {
    pub policy: (String, PolicyLanguage),
    pub c0: FP48,
    pub c1: HashMap<String, FP48>,
    pub c2: HashMap<String, ECP>,
    pub c3: HashMap<String, ECP>,
    pub c4: HashMap<String, ECP8>,
    pub ct: Vec<u8>,
}
const MSG_SIZE: usize = 48 * (MODBYTES as usize);

fn encrypt(
    mut rng: &mut RAND,
    gp: &GlobalParams,
    pks: &HashMap<String, AuthorityPublicKey>,
    policy: (String, PolicyLanguage),
    data: &[u8],
) -> Result<Ciphertext, ABEError> {
    let (policy_name, language) = policy;
    match parse(&policy_name, language) {
        Ok(policy) => {
            let mut s = BIG::random(&mut rng);
            s.rmod(&BIG::new_ints(&CURVE_ORDER)); // s = s mod q (order of G1)
            let w = BIG::new();

            let s_shares = gen_shares_policy(s, &policy, None).unwrap();
            let w_shares = gen_shares_policy(w, &policy, None).unwrap();

            let mut thread_rng = rand::thread_rng();
            let mut msg = [0; MSG_SIZE];
            thread_rng.fill_bytes(&mut msg);
            let mut c0 = FP48::frombytes(&msg);
            c0.tobytes(&mut msg);

            c0.mul(&pair8::gtpow(&gp.e, &s));
            let mut c1 = HashMap::new();
            let mut c2 = HashMap::new();
            let mut c3 = HashMap::new();
            let mut c4 = HashMap::new();

            for (attr_name, s_share) in s_shares.into_iter() {
                let tx = BIG::random(&mut rng);

                let authority_name = attr_name.split_once("@").unwrap().0;
                let attr = remove_index(&attr_name);

                let pk_attr = pks.get(authority_name);
                if let Some(authority_pk) = pk_attr {
                    let mut c1x = pair8::gtpow(&gp.e, &s_share);
                    c1x.mul(&pair8::gtpow(&authority_pk.e_alpha, &tx));
                    c1.insert(attr_name.clone(), c1x);

                    let mut c2x = pair8::g1mul(&gp.g1, &tx);
                    c2x.neg();
                    c2.insert(attr_name.clone(), c2x);

                    let mut c3x = pair8::g1mul(&authority_pk.gy, &tx);
                    c3x.add(&pair8::g1mul(&gp.g1, &w_shares.get(&attr_name).unwrap()));
                    c3.insert(attr_name.clone(), c3x);

                    let c4x = pair8::g2mul(&hash_to_g2(&attr), &tx);
                    c4.insert(attr_name.clone(), c4x);
                }
            }

            match encrypt_symmetric(msg, data) {
                Ok(ct) => Ok(Ciphertext { policy: (policy_name, language), c0, c1, c2, c3, c4, ct }),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(ABEError::new("Failed to parse policy")),
    }
}

fn decrypt(sk: &UserSecretKey, ct: &Ciphertext) -> Result<Vec<u8>, ABEError> {
    let (policy_name, lang) = ct.policy.clone();
    match parse(&policy_name, lang) {
        Ok(policy) => {
            let attributes = sk.inner.keys().map(|k| k.to_string()).collect::<Vec<_>>();
            match traverse_policy(&attributes, &policy, tessera_policy::pest::PolicyType::Leaf) {
                true => {
                    let pruned = calc_pruned(&attributes, &policy, None);
                    match pruned {
                        Ok((is_matched, matched_nodes)) => match is_matched {
                            true => {
                                let mut coefficients = HashMap::new();
                                coefficients = calc_coefficients(&policy, BIG::new_int(1), coefficients, None).unwrap();

                                let h_user = hash_to_g2(&sk.gid);
                                let mut b = FP48::new();
                                b.one();

                                for (attr, attr_and_index) in matched_nodes {
                                    let c1 = ct.c1.get(&attr_and_index).unwrap();
                                    let c2 = ct.c2.get(&attr_and_index).unwrap();
                                    let c3 = ct.c3.get(&attr_and_index).unwrap();
                                    let c4 = ct.c4.get(&attr_and_index).unwrap();
                                    let k = &sk.inner.get(&attr).unwrap().k;
                                    let kp = &sk.inner.get(&attr).unwrap().kp;

                                    let mut base = c1.clone();

                                    base.mul(&pair8::fexp(&pair8::ate(k, c2)));
                                    base.mul(&pair8::fexp(&pair8::ate(&h_user, c3)));
                                    base.mul(&pair8::fexp(&pair8::ate(c4, kp)));
                                    base = pair8::gtpow(&base, &coefficients.get(&attr_and_index).unwrap());
                                    b.mul(&base);
                                }

                                b.inverse();

                                let mut msg = ct.c0.clone();
                                msg.mul(&b);
                                println!("[Decrypt] M = {}", msg.tostring());

                                let mut msg_bytes = [0; MSG_SIZE];
                                msg.tobytes(&mut msg_bytes);
                                println!("[Decrypt] msg = {:?}", msg_bytes);

                                decrypt_symmetric(msg_bytes, &ct.ct)
                            }
                            false => Err(ABEError::new("Error: Attributes in user secret doesn't match policy.")),
                        },
                        Err(e) => Err(e),
                    }
                }
                false => Err(ABEError::new("Error: Attributes in user secret doesn't match policy.")),
            }
        }
        Err(e) => Err(ABEError::new("Failed to parse policy")),
    }
}

fn hash_to_g2(msg: &str) -> ECP8 {
    let mut hash = HASH256::new();
    hash.process_array(msg.as_bytes());
    let h = hash.hash();
    ECP8::mapit(&h)
}

fn main() {
    let mut rng = RAND::new();
    let mut thread_rng = rand::thread_rng();
    let mut seed = [0; 128];
    thread_rng.fill(&mut seed);
    rng.clean();
    rng.seed(128, &seed);
    let gp = GlobalParams::new(&mut rng);

    println!("Global parameters generated.");
    let authority_a = AuthorityKeyPair::new(&mut rng, &gp, "Aauthority");
    println!("Authority A generated.");
    let authority_b = AuthorityKeyPair::new(&mut rng, &gp, "Bauthority");
    println!("Authority B generated.");

    let mut alice =
        UserSecretKey::new(&mut rng, &gp, &authority_a.mk, "alice", &["Aauthority@ADMIN", "Aauthority@GOD"]);
    println!("Alice generated.");

    alice.add_attributes(&mut rng, &gp, &authority_b.mk, &["Bauthority@CTO"]);
    println!("Alice added attributes.");

    let alice_by_authority_b = UserSecretKey::new(&mut rng, &gp, &authority_b.mk, "alice", &["B_authority@CEO"]);

    let mut bob = UserSecretKey::new(&mut rng, &gp, &authority_a.mk, "bob", &["Aauthority@USER"]);
    println!("Bob generated.");
    bob.add_attributes(&mut rng, &gp, &authority_b.mk, &["Bauthority@CTO"]);
    println!("Bob added attributes.");
    let bob_by_authority_b = UserSecretKey::new(&mut rng, &gp, &authority_b.mk, "bob", &["B_authority@CTO"]);

    let plaintext = "THIS IS SECRET MESSAGE";
    let policy = r#""Aauthority@GOD" and "Bauthority@CTO""#;

    let mut pks = HashMap::new();
    pks.insert("Aauthority".to_string(), authority_a.pk);
    pks.insert("Bauthority".to_string(), authority_b.pk);
    let t = Instant::now();
    let ciphertext =
        encrypt(&mut rng, &gp, &pks, (policy.to_string(), PolicyLanguage::HumanPolicy), plaintext.as_bytes()).unwrap();
    println!("Time taken to encrypt: {:?}", t.elapsed());
    println!("Ciphertext generated.");

    let decrypt_text = decrypt(&alice, &ciphertext).unwrap();
    println!("Decrypted text: {:?}", String::from_utf8(decrypt_text).unwrap());
}
