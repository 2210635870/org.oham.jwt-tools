package org.oham.jwttools.utils;

/**
 * @Author 欧航
 * @Description 静态常量
 * @Date 2020/10/30 17:17
 * @Version 1.0
 **/
public class ConstantsUtil {
    /** RSA 算法名参数 */
    public static final String RSA_ALGORITHM = "RSA";

    /** ECDSA 算法名参数 */
    public static final String ECDSA_ALGORITHM = "EC";

    /** ECDSA 算法标准曲线参数 */
    public static final String ECDSA_P_256 = "secp256r1";
    public static final String ECDSA_SEC_P_256K1 = "secp256k1";
    public static final String ECDSA_P_384 = "secp384r1";
    public static final String ECDSA_P_512 = "secp512r1";

    /** 全局唯一 Key Id 前缀 */
    public static final String KEY_ID_PREFIX = "jwk";

    /** 有效 IPv4 最小长度 */
    public static final int IP_LEAST_LEN = 6;

    /** IPv4 片段数字补位长度 */
    public static final int IP_PART_LEN = 3;

    /** Key Id 线程计数器边界 */
    public static final int KEY_ID_SEQ_BOUND = 99990;

    /** 业务异常分割表达式 */
    public static final String ERR_MAG_PATTERN = "###(.*?)###";
}
