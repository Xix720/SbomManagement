package corse;

import Utils.CallGraphPathFinder;
import Utils.ComponentDownloader;
import Utils.JarCallGraphBuilder_ASM;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import corse.utils.JarDependencyExtractor;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class corsePathFinder {

    public static void main(String[] args) throws IOException {
        String downstream = "org.deeplearning4j:deeplearning4j-modelimport:1.0.0-M2.1";
        String upstream = "org.apache.commons:commons-compress:1.21";
        // 组件列表
        List<String> components = new ArrayList<>(Arrays.asList("org.nd4j:nd4j-native-api:1.0.0-M2.1", "org.nd4j:nd4j-common:1.0.0-M2.1"));

        // 模拟 JarDependencyExtractor 解析的依赖关系
        Map<String, Set<String>> wholeGraph = new HashMap<>();
        Map<String, Set<String>> componentClassesMap = new HashMap<>();
        for (String component : components) {
            String jarPath = ComponentDownloader.downloadComponent(component, "src/main/java/Jars");
            Map<String, Set<String>> thisComDependencies = JarDependencyExtractor.extractDependencyGraph(jarPath);
            componentClassesMap.put(component,thisComDependencies.keySet());
            wholeGraph = JarCallGraphBuilder_ASM.mergeCG(wholeGraph, thisComDependencies);
        }
        //下游组件
        String downstreamjarPath = ComponentDownloader.downloadComponent(downstream, "src/main/java/Jars");
        Map<String, Set<String>> downstreamComDependencies = JarDependencyExtractor.extractDependencyGraph(downstreamjarPath);
        wholeGraph = JarCallGraphBuilder_ASM.mergeCG(downstreamComDependencies, wholeGraph);

        //上游组件
        String upstreamjarPath = ComponentDownloader.downloadComponent(upstream, "src/main/java/Jars-CVE");
        Map<String, Set<String>> upstreamComDependencies = JarDependencyExtractor.extractDependencyGraph(upstreamjarPath);
        wholeGraph = JarCallGraphBuilder_ASM.mergeCG(upstreamComDependencies, wholeGraph);

        // 指定保存路径和文件名
        String filePath2 = "src/main/resources/callgraphs/call_corse.json"; // 指定保存路径
        saveMapToFile(wholeGraph, filePath2);

        for (String downStreamClass : downstreamComDependencies.keySet()) {
            List<String> path = new ArrayList<>();
            for (String upStreamClass : upstreamComDependencies.keySet()) {
                 path = CallGraphPathFinder.findPath(wholeGraph, downStreamClass, upStreamClass);
                if (!path.isEmpty()) {
                    System.out.println("找到路径：" + path);
                    break;
                }
            }
        }

    }
    public static void saveMapToFile(Map<String, Set<String>> map, String filePath) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create(); // 格式化 JSON

        // 确保目录存在
        File file = new File(filePath);
        File parentDir = file.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs(); // 创建目录
        }

        try (FileWriter writer = new FileWriter(file)) {
            gson.toJson(map, writer); // 将 Map 转为 JSON 格式并写入文件
            System.out.println("Map has been saved to " + filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
