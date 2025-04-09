package org.example;

import JarAnalyzer.Runner; // 导入 Runner 类，该类可能用于运行分析器

import java.util.Map; // 导入 Map 接口，用于存储键值对

/**
 * 主程序类，用于启动和运行依赖分析器。
 * 该程序通过 Runner 类调用 runAnalyzer_java 方法，分析下游组件针对上游组件的漏洞是否有可达路径，
 * 并输出与指定 CVE（Common Vulnerabilities and Exposures）相关的分析结果。
 */
public class Main {
    public static void main(String[] args) {
        // 定义上游依赖库的坐标，格式为 "groupId:artifactId:version"。
        // 这里指定的是 commons-io 库，版本为 2.4。
        String upstream = "commons-io:commons-io:2.4";

        // 定义下游依赖库的坐标，格式为 "groupId:artifactId:version"。
        // 这里指定的是 deeplearning4j-nn 库，版本为 0.9.1。
        String downstream = "org.deeplearning4j:deeplearning4j-nn:0.9.1";

        // 创建 Runner 类的实例，Runner 类可能用于运行依赖分析器。
        Runner runner = new Runner();

        // 调用 Runner 类的 runAnalyzer_java 方法，传入上游依赖、下游依赖和一个 CVE 编号。
        // 该方法用于分析两个组件之间针对某个漏洞CVE的可达性
        // 返回值是一个 Map，其中包含分析结果。
        Map<String, Object> stringObjectMap = runner.runAnalyzer_java(upstream, downstream, "CVE-2021-29425");

        // 将分析结果打印到控制台。
        System.out.println(stringObjectMap);
    }
}