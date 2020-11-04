package org.oham.jwttools;

import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import lombok.Builder;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.oham.jwttools.utils.KeyUtil;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * @Author 欧航
 * @Description 已提供的 ECDSA 密钥对 ECDSA Provider 接口
 * @Date 2020/11/2 15:25
 * @Version 1.0
 **/
@Slf4j
@Builder
class ProvidedEcdsaKeyPairProvider implements ECDSAKeyProvider {

    private final String srcPrivateKey;

    private final String srcPublicKey;

    @Override
    public ECPublicKey getPublicKeyById(String s) {

        ECPublicKey pub = null;
        try {
            pub = KeyUtil.restoreEcdsaPublicKey(srcPublicKey);
        } catch (Exception e) {
            log.error("还原 ECDSAPublicKey 对象失败", e);
        }
        return pub;
    }

    @Override
    public ECPrivateKey getPrivateKey() {
        ECPrivateKey pri = null;
        try {
            pri = KeyUtil.restoreEcdsaPrivateKey(srcPrivateKey);
        } catch (Exception e) {
            log.error("还原 ECDSAPrivateKey 对象失败", e);
        }
        return pri;
    }

    @Override
    public String getPrivateKeyId() {
        return null;
    }
}
