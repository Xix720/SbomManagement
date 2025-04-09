import Utils.*;
import Utils.JarCallGraphBuilder_ASM;

import Utils.ComponentDownloader;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Main {
    public static void main(String[] args){
        //输入上下游组件
        Scanner scanner = new Scanner(System.in);

        System.out.println("--------------------------------欢迎使用漏洞可达性分析系统-------------------------------------");
        System.out.println("请输入上游组件的GAV：");
        String upstreamComponent = scanner.nextLine();

        System.out.println("请输入下游组件的名称GAV：");
        String downstreamComponent = scanner.nextLine();

        //设置组件下载的位置
        String jars_cve_path = "src/main/Jars-CVE";
        String jars_targetJar_path = "src/main/Jars";
        //下载组件
        System.out.println("正在获取组件...");
        String CVEJarPath = ComponentDownloader.downloadComponent(upstreamComponent, jars_cve_path);
        String targetJarPath = ComponentDownloader.downloadComponent(downstreamComponent, jars_targetJar_path);

        //CVE.csv文件，获取sink点合集
        System.out.println("---------------------------正在获取sink点----------------------------------");
        String csvPath = "src/main/CSVs/CVE.csv";
        Map<String, Set<String>> CVE_sinkPoints = CsvDealer.processCSV(csvPath, "CVE_ID", "VUL_FUNs");
        System.out.println("Complete!");

        System.out.println("---------------------------正在构建调用图----------------------------------");
        //构建危险jar包和待检测jar包的调用图
        Map<String, Set<String>> CVEJarCG = JarCallGraphBuilder_ASM.generateJarCG(CVEJarPath);
        // 指定保存路径和文件名
        String filePath1 = "src/main/resources/callgraphs/call_up.json"; // 指定保存路径
        saveMapToFile(CVEJarCG, filePath1);

        Map<String, Set<String>> targetJarCG = JarCallGraphBuilder_ASM.generateJarCG(targetJarPath);
        // 指定保存路径和文件名
        String filePath2 = "src/main/resources/callgraphs/call_down.json"; // 指定保存路径
        saveMapToFile(targetJarCG, filePath2);

        //融合调用图
        Map<String, Set<String>> wholeCG = JarCallGraphBuilder_ASM.mergeCG(CVEJarCG, targetJarCG);
        // 指定保存路径和文件名
        String filePath = "src/main/resources/callgraphs/call.json"; // 指定保存路径
        saveMapToFile(wholeCG, filePath);
        System.out.println("Complete!");

        System.out.println("---------------------------正在分析可达路径----------------------------------");
        System.out.println("请输入需要检测的CVE(可选):");
        String keyword = scanner.nextLine();
        System.out.println(keyword);
        scanner.close();
        if (!keyword.equals(""))
            CVE_sinkPoints = CsvDealer.searchForKeyword(CVE_sinkPoints,keyword);

        // 创建一个map存储所有结果
        Map<String, Object> result = new LinkedHashMap<>();

        //创建一个漏洞map
        Map<String, Object> vulMap = new LinkedHashMap<>();

        //遍历CVE的sink点
        for(Map.Entry<String, Set<String>> entry : CVE_sinkPoints.entrySet()){
            String thisCVE = entry.getKey();
            Set<String> sinkPoints = entry.getValue();
            System.out.println("-------------------正在分析 " + thisCVE + "-----------------------");
            List<Map<String,Object>> thisCVEResult = new ArrayList<>();
            for (String sinkPoint : sinkPoints){
                //sink点格式与调用图中点的格式保持一致
                String sinkPoint_ASM = changeMethodFormat(sinkPoint, CVEJarCG);

                //如果sink点为null，则说明调用图中没有sink点，continue
                if (sinkPoint_ASM.equals("null")){
                    Map<String,Object> map = new LinkedHashMap<>();
                    map.put("sink点", sinkPoint);
                    map.put("可达性结果", false);
                    thisCVEResult.add(map);
                    continue;
                }else
                    sinkPoint = sinkPoint_ASM;

                //是否找到路径
                boolean isFound = false;

                //创建map存储当前sink点的检测结果
                Map<String, Object> thisSinkResult = new LinkedHashMap<>();
                //创建一个可达路径的列表
                List<List<String>> pathList = new ArrayList<>();
                for (String sourcePoint : targetJarCG.keySet()){
                    List<String> hasPath = CallGraphPathFinder.findPath(wholeCG, sourcePoint, sinkPoint);
                    //如果有路径则加入路径列表中
                    if (!hasPath.isEmpty()){
                        isFound = true;
                        //规范可达路径的格式
                        List<String> pathResult = new ArrayList<>();
                        for (int i = hasPath.size()-1; i>=0; i--){
                            pathResult.add(PointFormator.format_Soot(hasPath.get(i)));
                        }
                        pathList.add(pathResult);
                    }
                }
                thisSinkResult.put("Sink点：" , PointFormator.format_Soot(sinkPoint));
                thisSinkResult.put("可达性结果：" , isFound);
                if (isFound && !pathList.isEmpty()){
                    thisSinkResult.put("可达性路径：" , removeDuplicatedPath(pathList));
                }
                //将当前sink点的路径加入列表中
                thisCVEResult.add(thisSinkResult);
            }
            vulMap.put(thisCVE, thisCVEResult);
        }
        //将漏洞列表存储进结果
        result.put("上游组件：" , upstreamComponent);
        result.put("下游组件：" , downstreamComponent);
        result.put("漏洞列表", vulMap);

        // 使用Gson将Map转换为JSON字符串
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.setPrettyPrinting();
        String jsonString = gsonBuilder.disableHtmlEscaping().create().toJson(result);

        try {
            // 创建输出 JSON 文件的 FileWriter
            String directoryPath  = "src/main/Results/";
            // 创建一个 File 对象表示目录
            File directory = new File(directoryPath);
            // 检查目录是否存在
            if (directory.mkdirs()) {
                System.out.println("Directory created successfully.");
            }
            FileWriter fileWriter = new FileWriter(directoryPath + downstreamComponent.replace(":", "^") +
                    "_" + upstreamComponent.replace(":", "^")  + ".json");

            fileWriter.write(jsonString);

            // 关闭 FileWriter
            fileWriter.close();

            System.out.println("JSON file successfully written.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static List<List<String>> removeDuplicatedPath(List<List<String>> pathList){
        int i = 0;
        // 按长度排序
        Collections.sort(pathList, Comparator.comparingInt(List::size));
        for (List<String> path : pathList){
            if (!pathList.get(i).stream().allMatch(path :: contains)){
                pathList.set(++i, path);
            }
        }
        return pathList.subList(0, ++i);
    }

    public static String changeMethodFormat(String sinkPoint, Map<String, Set<String>> callMap_CVEJar){
        //返回 类路径:方法名
        boolean isfound = false;
        String methodName = sinkPoint.split("\\(")[0];
        for (Map.Entry<String, Set<String>> ee : callMap_CVEJar.entrySet()){
            String caller = ee.getKey();
            Set<String> callees = ee.getValue();
            if (caller.contains(methodName)){
                //如果找到匹配的被调用方法名就完整赋值给methodName
                methodName = caller;
                isfound = true;
                break;
            }
            for (String callee : callees){
                if (callee.startsWith(methodName)){
                    //如果找到匹配的被调用方法名就完整赋值给methodName
                    methodName = callee;
                    isfound = true;
                    break;
                }
            }
        }
        //如果调用图中没找到sink点，则返回null
        if (!isfound)
            methodName = "null";
        return methodName;
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

