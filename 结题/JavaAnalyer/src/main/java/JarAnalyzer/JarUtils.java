package JarAnalyzer;

import java.io.IOException;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarUtils {
    public static Map<String, Set<String>> extractClasses(String jarFilePath) {
        Map<String, Set<String>> jarClassMap = new HashMap<>();

        try (JarFile jarFile = new JarFile(jarFilePath)) {
            Enumeration<JarEntry> entries = jarFile.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();

                // 只处理以".class"结尾的类文件
                if (entry.getName().endsWith(".class")) {
                    String className = entry.getName().replace("/", ".").replace(".class", "");
                    String jarName = jarFile.getName();

                    // 获取或创建JAR包对应的类名集合
                    Set<String> classSet = jarClassMap.computeIfAbsent(jarName, k -> new HashSet<>());
                    classSet.add(className);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return jarClassMap;
    }

}




