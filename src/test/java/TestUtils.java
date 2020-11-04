import org.oham.jwttools.utils.PropsUtil;
import org.testng.annotations.Test;

/**
 * @Author 欧航
 * @Description 测试工具类
 * @Date 2020/11/4 11:09
 * @Version 1.0
 **/
public class TestUtils {

    @Test
    public void testPropsReload() {
        PropsUtil.reload();
    }
}
