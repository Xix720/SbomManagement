import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class testListSort {
    @Test
    public void testListSort() {
        List<List<String>> list = new ArrayList<List<String>>();

        List<String> list0 = new ArrayList<>();
        list0.add("de.codedo.jaas.PamLoginModule:performLogin()");

        List<String> list1 = new ArrayList<>();
        list1.add("de.codedo.jaas.PamLoginModule:performLogin()");
        list1.add("org.jvnet.libpam.PAM:authenticate(java.lang.String,java.lang.String)");

        List<String> list2 = new ArrayList<>();
        list2.add("de.codedo.jaas.PamLoginModule:login()");
        list2.add("de.codedo.jaas.PamLoginModule:performLogin()");
        list2.add("org.jvnet.libpam.PAM:authenticate(java.lang.String,java.lang.String)");

        list.add(list1);
        list.add(list2);
        list = Main.removeDuplicatedPath(list);
        System.out.println(list);

    }
}
