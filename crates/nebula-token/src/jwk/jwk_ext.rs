use anyhow::anyhow;
use josekit::jwk::Jwk;
use josekit::jws::{
    EdDSA, JwsSigner, JwsVerifier, ES256, ES256K, ES384, ES512, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384,
    RS512,
};
use josekit::jwt::alg::unsecured::UnsecuredJwsAlgorithm;
use josekit::JoseError;

pub trait JwkExt {
    fn get_signer(&self) -> Result<Box<dyn JwsSigner>, JoseError>;
    fn get_verifier(&self) -> Result<Box<dyn JwsVerifier>, JoseError>;
}

impl JwkExt for Jwk {
    fn get_signer(&self) -> Result<Box<dyn JwsSigner>, JoseError> {
        let alg =
            &self.algorithm().ok_or_else(|| JoseError::InvalidJwkFormat(anyhow!("Missing alg in JWK")))?.to_uppercase()
                [..];

        let signer: Box<dyn JwsSigner> = match alg {
            "ES256" => Box::new(ES256.signer_from_jwk(self)?),
            "ES384" => Box::new(ES384.signer_from_jwk(self)?),
            "ES512" => Box::new(ES512.signer_from_jwk(self)?),
            "ES256K" => Box::new(ES256K.signer_from_jwk(self)?),
            "EDDSA" => Box::new(EdDSA.signer_from_jwk(self)?),
            "RS256" => Box::new(RS256.signer_from_jwk(self)?),
            "RS384" => Box::new(RS384.signer_from_jwk(self)?),
            "RS512" => Box::new(RS512.signer_from_jwk(self)?),
            "PS256" => Box::new(PS256.signer_from_jwk(self)?),
            "PS384" => Box::new(PS384.signer_from_jwk(self)?),
            "PS512" => Box::new(PS512.signer_from_jwk(self)?),
            "HS256" => Box::new(HS256.signer_from_jwk(self)?),
            "HS384" => Box::new(HS384.signer_from_jwk(self)?),
            "HS512" => Box::new(HS512.signer_from_jwk(self)?),
            "none" => Box::new(UnsecuredJwsAlgorithm::None.signer()),
            _ => unreachable!("should be unreachable"),
        };
        Ok(signer)
    }

    fn get_verifier(&self) -> Result<Box<dyn JwsVerifier>, JoseError> {
        let alg =
            &self.algorithm().ok_or_else(|| JoseError::InvalidJwkFormat(anyhow!("Missing alg in JWK")))?.to_uppercase()
                [..];

        let verifier: Box<dyn JwsVerifier> = match alg {
            "ES256" => Box::new(ES256.verifier_from_jwk(self)?),
            "ES384" => Box::new(ES384.verifier_from_jwk(self)?),
            "ES512" => Box::new(ES512.verifier_from_jwk(self)?),
            "ES256K" => Box::new(ES256K.verifier_from_jwk(self)?),
            "EDDSA" => Box::new(EdDSA.verifier_from_jwk(self)?),
            "RS256" => Box::new(RS256.verifier_from_jwk(self)?),
            "RS384" => Box::new(RS384.verifier_from_jwk(self)?),
            "RS512" => Box::new(RS512.verifier_from_jwk(self)?),
            "PS256" => Box::new(PS256.verifier_from_jwk(self)?),
            "PS384" => Box::new(PS384.verifier_from_jwk(self)?),
            "PS512" => Box::new(PS512.verifier_from_jwk(self)?),
            "HS256" => Box::new(HS256.verifier_from_jwk(self)?),
            "HS384" => Box::new(HS384.verifier_from_jwk(self)?),
            "HS512" => Box::new(HS512.verifier_from_jwk(self)?),
            "none" => Box::new(UnsecuredJwsAlgorithm::None.verifier()),
            _ => unreachable!("should be unreachable"),
        };
        Ok(verifier)
    }
}
