## 基于 com.auth0:java-jwt 做的一个 Json Web Token 简单封装库
https://travis-ci.com/github/2210635870/org.oham.jwt-tools
[![Build Status](https://api.travis-ci.com/2210635870/org.oham.jwt-tools.svg?branch=main)](https://travis-ci.com/github/2210635870/org.oham.jwt-tools)
[![Coverage Status](https://codecov.io/gh/2210635870/org.oham.jwt-tools/badge.svg?branch=main)](https://codecov.io/gh/2210635870/org.oham.jwt-tools?branch=main)

支持如下加密算法：
* HS256: HMAC using SHA-256
* HS384: HMAC using SHA-384
* HS512: HMAC using SHA-512
* ES256: ECDSA using curve P-256 and SHA-256
* ES256K: ECDSA using curve secp256k1 and SHA-256
* ES384: ECDSA using curve P-384 and SHA-384
* ES512: ECDSA using curve P-521 and SHA-521
* RS256: RSASSA-PKCS1-v1_5 with SHA-256
* RS384: RSASSA-PKCS1-v1_5 with SHA-384
* RS512: RSASSA-PKCS1-v1_5 with SHA-512

<br/>

##### 创建一个 Token:
````
JwkVo jwkVo = AlgorithmEnum.HS256.initJwkVO();
jwkVo.setPrivateExponent("test-secret-key");

// token 失效日期（60分钟有效时长）
Date expiredAt = Date.from(
        LocalDateTime.now().plusMinutes(60)
        .atZone(ZoneId.systemDefault()).toInstant());

JWTCreator.Builder jwtBuilder = JWT.create()
        .withIssuer("org.oham")                            // 设置 token 发行者
        .withKeyId(jwkVo.getKid())                         // 设置 token key id
        .withIssuedAt(Calendar.getInstance().getTime())    // 设置 token 发行日期
        .withExpiresAt(expiredAt);                         // 设置 token 失效日期 （60分钟有效时长）

String token = JwtTools.createToken(jwkVo, jwtBuilder);

````

<br/>

##### 创建一个 基于 RSA 签名算法的 Token:
````
JwkVo jwkVo = AlgorithmEnum.RSA384.initJwkVO();
// 生成并设置 RSA 密钥对
RsaKeyPairVo rsaKeyPairVo = KeyUtil.generateRsaKeyPair();
jwkVo.setPrivateExponent(rsaKeyPairVo.getPrivateKeyStr());
jwkVo.setPublicExponent(rsaKeyPairVo.getPublicKeyStr());

// token 失效日期（60分钟有效时长）
Date expiredAt = Date.from(
        LocalDateTime.now().plusMinutes(60)
        .atZone(ZoneId.systemDefault()).toInstant());

JWTCreator.Builder jwtBuilder = JWT.create()
        .withIssuer("org.oham")                            // 设置 token 发行者
        .withKeyId(jwkVo.getKid())                         // 设置 token key id
        .withIssuedAt(Calendar.getInstance().getTime())    // 设置 token 发行日期
        .withExpiresAt(expiredAt);                         // 设置 token 失效日期 （60分钟有效时长）

String token = JwtTools.createToken(jwkVo, jwtBuilder);

````

<br/>

##### 创建一个 基于 ECDSA 签名算法的 Token:
````
JwkVo jwkVo = AlgorithmEnum.ES256.initJwkVO();
// 生成并设置 ECDSA 密钥对
EcdsaKeyPairVo ecdsaKeyPairVo = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_P_256);
jwkVo.setPrivateExponent(ecdsaKeyPairVo.getPrivateKeyStr());
jwkVo.setPublicExponent(ecdsaKeyPairVo.getPublicKeyStr());

JWTCreator.Builder jwtBuilder = JWT.create()
        .withIssuer("org.oham")                            // 设置 token 发行者
        .withKeyId(jwkVo.getKid())                         // 设置 token key id
        .withIssuedAt(Calendar.getInstance().getTime())    // 设置 token 发行日期
        .withExpiresAt(expiredAt);                         // 设置 token 失效日期 （60分钟有效时长）

String token = JwtTools.createToken(jwkVo, jwtBuilder);

````
<br/>

##### Token 验签:
````
// Jwk 已事先设置好签名算法以及对应的公私玥（对称签名算法不用公钥）
JwkVo jwkVo = AlgorithmEnum.ES256.initJwkVO();
jwkVo.setPrivateExponent("已知的私钥");
jwkVo.setPublicExponent("已知的公钥");

// 验签，不通过则抛出 SignatureVerificationException 异常；
DecodedJWT decodedJWT = JwtTools.verifySign(jwkVo, token);
log.debug("Decoded token header: {} \npayload: {}\nsignature: {}\nkey id: {}\nexpireAt: {}\nalgorithm: {}",
        new String(Base64.decodeBase64(jwt.getHeader()), Charset.defaultCharset()),
        new String(Base64.decodeBase64(jwt.getPayload()), Charset.defaultCharset()),
        jwt.getSignature(),
        jwt.getKeyId(),
        LocalDateTime.ofInstant(jwt.getExpiresAt().toInstant(),
                ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
        jwt.getAlgorithm());

````
