package JarAnalyzer;

import org.springframework.core.io.ClassPathResource;

import java.io.*;
import java.util.*;
public class Runner {
    // 运行java可达性分析
    public Map<String, Object> runAnalyzer_java (String upstreamComponent, String thisProject, String keyword) {

        //设置组件下载的位置
        String jars_cve_path = "src/main/java/CVEJars";
        String jars_path = "src/main/java/Jars";

        File jars_cve = new File(jars_cve_path);

        // 检查文件夹是否存在，如果不存在则创建
        if (!jars_cve.exists()) {
            if (jars_cve.mkdir()) {
                System.out.println("Successfully Created: " + jars_cve.getAbsolutePath());
            } else {
                System.out.println("Failed to create folder.");
            }
        } else {
            System.out.println("Jars-CVE folder already exists at: " + jars_cve.getAbsolutePath());
        }

        File jars = new File(jars_path);

        // 检查文件夹是否存在，如果不存在则创建
        if (!jars.exists()) {
            if (jars.mkdir()) {
                System.out.println("Successfully Created: " + jars.getAbsolutePath());
            } else {
                System.out.println("Failed to create folder.");
            }
        } else {
            System.out.println("Jars folder already exists at: " + jars.getAbsolutePath());
        }

        //下载依赖的组件
        System.out.println("正在获取组件...");
        String CVEJarPath = ComponentDownloader.downloadComponent(upstreamComponent, jars_cve_path);
        String thisProjectPath  = ComponentDownloader.downloadComponent(thisProject, jars_path);

        //CVE.csv文件，获取sink点合集
        // 正在获取sink点
        Map<String, Set<String>> CVE_sinkPoints  = new HashMap<>();
        ClassPathResource CSVResource = new ClassPathResource("/CSVs/CVE.csv");
        try (InputStream inputStream = CSVResource.getInputStream()) {
            CVE_sinkPoints = CsvDealer.processCSV(inputStream, "CVE_ID", "VUL_FUNs");
            System.out.println("Complete!");
        } catch (IOException e) {
            e.printStackTrace();
        }
//        String csvPath = "src/main/resources/datasets/CSVs/CVE.csv";
        if (CVE_sinkPoints.isEmpty()) {
            System.out.println("sink点获取失败");
            return null;
        }

        //正在构建调用图
        //构建危险jar包调用图
        Map<String, Set<String>> CVEJarCG = JarCallGraphBuilder_ASM.generateJarCG(CVEJarPath);

        //构建待检测项目目录的调用图
        Map<String, Set<String>> targetJarCG = JarCallGraphBuilder_ASM.generateJarCG(thisProjectPath);

        //融合调用图
        Map<String, Set<String>> wholeCG = JarCallGraphBuilder_ASM.mergeCG(CVEJarCG, targetJarCG);

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
                thisSinkResult.put("sink点" , PointFormator.format_Soot(sinkPoint));
                thisSinkResult.put("可达性结果" , isFound);
                if (isFound && !pathList.isEmpty()){
                    thisSinkResult.put("可达性路径" , removeDuplicatedPath(pathList));
                }
                //将当前sink点的路径加入列表中
                thisCVEResult.add(thisSinkResult);
            }
            vulMap.put(thisCVE, thisCVEResult);
        }
        //将漏洞列表存储进结果
        result.put("上游组件" , upstreamComponent);
        result.put("下游组件" , thisProject);
        result.put("漏洞列表", vulMap);

        return result; //返回分析结果
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
            if (caller.startsWith(methodName)){
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
}
