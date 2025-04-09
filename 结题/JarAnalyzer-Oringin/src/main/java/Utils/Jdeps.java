package Utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

//分析项目调用的第三方类
public class Jdeps {

    public static Map<String, Set<String>> analyzeDependencies(String jarFilePath) {
        Map<String,  Set<String>> dependencyMap = new HashMap<>();

        try {
            Process process = Runtime.getRuntime().exec("jdeps -v " + jarFilePath);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = reader.readLine()) != null) {
                // Parsing the jdeps output to extract dependencies
                String[] parts = line.split(" -> ");
                if (parts.length == 2) {

                    String className = parts[0].trim();
                    String dependency = parts[1].trim().split("\\s+")[0];
                    if (!className.endsWith(".jar")&& !dependency.startsWith("java") && !isSelfCall(className, dependency)){
                        //移除自己对自己的调用
                        Set<String> set = dependencyMap.get(className);
                        // 如果键不存在，则创建一个新的 Set
                        if (set == null) {
                            set = new HashSet<>();
                            dependencyMap.put(className, set);
                        }
                        // 添加元素到 Set
                        set.add(dependency);
                    }

                }
            }

            process.waitFor();
            process.destroy();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        return dependencyMap;
    }

    public static boolean isSelfCall(String className, String calleeClass){
        String[] callerPack = className.split("\\.");
        String[] calleePack = calleeClass.split("\\.");
        int flag = 0;
        if (calleePack.length == callerPack.length){
            for (int i = 0; i<3; i++){
                if(callerPack[i].equals(calleePack[i]))
                    flag++;
            }
        }else {
            return false;
        }

        if (flag>=3)
            return true;
        else
            return false;
    }

    public static void main(String[] args) {
        String jarFilePath = "src/main/Jars/tynamo-federatedaccounts-core-0.7.0.jar";

        Map<String, Set<String>> dependencies = analyzeDependencies(jarFilePath);

        // Displaying the dependencies
        for (Map.Entry<String, Set<String>> entry : dependencies.entrySet()) {
            System.out.println("Class: " + entry.getKey());
            System.out.println("Dependencies: ");
            for (String ca : entry.getValue())
                System.out.println(ca);
            System.out.println("------------------------");
        }
    }
}
