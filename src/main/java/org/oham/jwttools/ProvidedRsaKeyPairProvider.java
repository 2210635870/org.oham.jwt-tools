package org.oham.jwttools;

import com.auth0.jwt.interfaces.RSAKeyProvider;
import lombok.Builder;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.oham.jwttools.utils.KeyUtil;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @Author 欧航
 * @Description 已提供的 RSA 密钥对 RSA Provider 接口
 * @Date 2020/10/30 15:31
 * @Version 1.0
 **/
@Slf4j
@Builder
class ProvidedRsaKeyPairProvider implements RSAKeyProvider {

    private final String srcPrivateKey;

    private final String srcPublicKey;

    @Override
    public RSAPublicKey getPublicKeyById(String s) {
        RSAPublicKey pub = null;
        try {
            pub = KeyUtil.restoreRsaPublicKey(srcPublicKey);
        } catch (Exception e) {
            log.error("还原 RSAPublicKey 对象失败", e);
        }
        return pub;
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        RSAPrivateKey pri = null;
        try {
            pri = KeyUtil.restoreRsaPrivateKey(srcPrivateKey);
        } catch (Exception e) {
            log.error("还原 RSAPrivateKey 对象失败", e);
        }
        return pri;
    }

    @Override
    public String getPrivateKeyId() {
        return null;
    }
}
