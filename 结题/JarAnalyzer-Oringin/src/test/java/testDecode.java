import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.Test;
import sun.nio.cs.ext.ISO2022_CN;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class testDecode {
    @Test
    public void test() throws UnsupportedEncodingException {
        String encodeString = "org.apache.xml.security.utils.UnsyncByteArrayOutputStream:<init>()";

        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.setPrettyPrinting();
        String gsonStr = gsonBuilder.disableHtmlEscaping().create().toJson(encodeString);

        System.out.println(gsonStr);


    }
}
