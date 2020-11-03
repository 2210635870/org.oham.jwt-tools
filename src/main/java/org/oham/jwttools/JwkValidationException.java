package org.oham.jwttools;

import lombok.Data;

/**
 * @Author 欧航
 * @Description JWK VO 校验异常
 * @Date 2020/11/3 16:53
 * @Version 1.0
 **/
@Data
public class JwkValidationException extends RuntimeException {
    private static final long serialVersionUID = 1830546656416441439L;

    /** 异常信息 */
    private String errorMsg;

    /** 异常信息代码 */
    private String errorCode;

    public JwkValidationException(Throwable cause) {
        super(cause);
    }

    public JwkValidationException(String message) {
        super(message);
        this.setErrorMsg(message);
    }

    public JwkValidationException(String message, Throwable cause) {
        super(message, cause);
        this.setErrorMsg(message);
    }

    public JwkValidationException(String errorCode, String errorMsg) {
        super(errorMsg);
        this.setErrorCode(errorCode);
        this.setErrorMsg(errorMsg);
    }
}
