use anyhow::anyhow;
use josekit::jwe::{
    Dir, JweDecrypter, JweEncrypter, A128GCMKW, A128KW, A192GCMKW, A192KW, A256GCMKW, A256KW, ECDH_ES, ECDH_ES_A128KW,
    ECDH_ES_A192KW, ECDH_ES_A256KW, RSA_OAEP, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512,
};
use josekit::jwk::Jwk;
use josekit::jws::{
    EdDSA, JwsSigner, JwsVerifier, ES256, ES256K, ES384, ES512, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384,
    RS512,
};
use josekit::jwt::alg::unsecured::UnsecuredJwsAlgorithm;
use josekit::JoseError;
use serde_json::Value;

pub trait JwkExt {
    fn get_signer(&self) -> Result<Box<dyn JwsSigner>, JoseError>;
    fn get_verifier(&self) -> Result<Box<dyn JwsVerifier>, JoseError>;
    fn get_decrypter(&self) -> Result<Box<dyn JweDecrypter>, JoseError>;
    fn get_encrypter(&self) -> Result<Box<dyn JweEncrypter>, JoseError>;

    fn x509_certificate_sha256_thumbprint_b64(&self) -> Option<&String>;
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

    fn get_decrypter(&self) -> Result<Box<dyn JweDecrypter>, JoseError> {
        let alg =
            &self.algorithm().ok_or_else(|| JoseError::InvalidJwkFormat(anyhow!("Missing alg in JWK")))?.to_uppercase()
                [..];
        let decrypter: Box<dyn JweDecrypter> = match alg {
            "dir" => Box::new(Dir.decrypter_from_jwk(self)?),
            "A128GCMKW" => Box::new(A128GCMKW.decrypter_from_jwk(self)?),
            "A192GCMKW" => Box::new(A192GCMKW.decrypter_from_jwk(self)?),
            "A256GCMKW" => Box::new(A256GCMKW.decrypter_from_jwk(self)?),
            "A128KW" => Box::new(A128KW.decrypter_from_jwk(self)?),
            "A192KW" => Box::new(A192KW.decrypter_from_jwk(self)?),
            "A256KW" => Box::new(A256KW.decrypter_from_jwk(self)?),
            "ECDH-ES" => Box::new(ECDH_ES.decrypter_from_jwk(self)?),
            "ECDH-ES+A128KW" => Box::new(ECDH_ES_A128KW.decrypter_from_jwk(self)?),
            "ECDH-ES+A192KW" => Box::new(ECDH_ES_A192KW.decrypter_from_jwk(self)?),
            "ECDH-ES+A256KW" => Box::new(ECDH_ES_A256KW.decrypter_from_jwk(self)?),
            "RSA-OAEP" => Box::new(RSA_OAEP.decrypter_from_jwk(self)?),
            "RSA-OAEP-256" => Box::new(RSA_OAEP_256.decrypter_from_jwk(self)?),
            "RSA-OAEP-384" => Box::new(RSA_OAEP_384.decrypter_from_jwk(self)?),
            "RSA-OAEP-512" => Box::new(RSA_OAEP_512.decrypter_from_jwk(self)?),
            _ => unreachable!("should be unreachable"),
        };
        Ok(decrypter)
    }

    fn get_encrypter(&self) -> Result<Box<dyn JweEncrypter>, JoseError> {
        let alg =
            &self.algorithm().ok_or_else(|| JoseError::InvalidJwkFormat(anyhow!("Missing alg in JWK")))?.to_uppercase()
                [..];
        let encrypter: Box<dyn JweEncrypter> = match alg {
            "dir" => Box::new(Dir.encrypter_from_jwk(self)?),
            "A128GCMKW" => Box::new(A128GCMKW.encrypter_from_jwk(self)?),
            "A192GCMKW" => Box::new(A192GCMKW.encrypter_from_jwk(self)?),
            "A256GCMKW" => Box::new(A256GCMKW.encrypter_from_jwk(self)?),
            "A128KW" => Box::new(A128KW.encrypter_from_jwk(self)?),
            "A192KW" => Box::new(A192KW.encrypter_from_jwk(self)?),
            "A256KW" => Box::new(A256KW.encrypter_from_jwk(self)?),
            "ECDH-ES" => Box::new(ECDH_ES.encrypter_from_jwk(self)?),
            "ECDH-ES+A128KW" => Box::new(ECDH_ES_A128KW.encrypter_from_jwk(self)?),
            "ECDH-ES+A192KW" => Box::new(ECDH_ES_A192KW.encrypter_from_jwk(self)?),
            "ECDH-ES+A256KW" => Box::new(ECDH_ES_A256KW.encrypter_from_jwk(self)?),
            "RSA-OAEP" => Box::new(RSA_OAEP.encrypter_from_jwk(self)?),
            "RSA-OAEP-256" => Box::new(RSA_OAEP_256.encrypter_from_jwk(self)?),
            "RSA-OAEP-384" => Box::new(RSA_OAEP_384.encrypter_from_jwk(self)?),
            "RSA-OAEP-512" => Box::new(RSA_OAEP_512.encrypter_from_jwk(self)?),
            _ => unreachable!("should be unreachable"),
        };
        Ok(encrypter)
    }

    fn x509_certificate_sha256_thumbprint_b64(&self) -> Option<&String> {
        match self.as_ref().get("x5t#S256") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }
}
