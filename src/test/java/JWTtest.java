import com.zhaozhiguang.component.jwt.JWT;
import com.zhaozhiguang.component.jwt.algorithms.Algorithm;
import com.zhaozhiguang.component.jwt.interfaces.DecodedJWT;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWTtest {

    @Test
    public void JWTTest() throws UnsupportedEncodingException {

        Map<String, Object> map = new HashMap<>();
        map.put("hh","value1");
        String secret = JWT.create().withExpiresAt(new Date(125555555555555l)).withParameters(map).sign(Algorithm.HMAC256("secret"));
        System.err.println(secret);

        DecodedJWT decode = JWT.decode(secret);

        //map.put("hh","value");
        DecodedJWT secret1 = JWT.require(Algorithm.HMAC256("secret")).withParameters(map).build().verify(secret);

        System.err.println(decode.getParameters());

    }
}
