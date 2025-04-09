package JarAnalyzer;

import java.util.Map;
import java.util.Set;

public class PointFormator {
    private static final String regex3 = "\\[[A-Z]{2}|^[A-Z]\\[[A-Z]";
    private static final String regex2 = "^[A-Z]{2}|\\[[A-Z]";
    private static final String regex1 = "^[A-Z]|^\\[";

    public static String format_Soot(String point){
        String result = "";
        //拆分类路径和方法
        String[] clazzPath_method = point.split(":");
        if(clazzPath_method.length == 1){
            // 过滤掉基本类型数组，如 [I, [D, [F, [J
            if (point.startsWith("[") && point.length() == 2) {
                return "null";  // 或者直接 return null;
            }
            //粗粒度顶点情况
            String newPoint = point.substring(0, point.lastIndexOf(".")) + ":" + point.substring(point.lastIndexOf(".")+1);
            if (newPoint.matches(regex3)) {
                result = newPoint.substring(3);
            }else if (newPoint.matches(regex2)) {
                result = newPoint.substring(2);
            }else if(newPoint.matches(regex1)) {
                result = newPoint.substring(1);
            }else if (newPoint.startsWith("[L") && newPoint.endsWith(";")) {
                    return newPoint.substring(2, newPoint.length() - 1).replace('/', '.');
            }else
                result = newPoint;

            return result;
        }
        String clazzPath = clazzPath_method[0];
        String methodName_types =clazzPath_method[1];
//        System.out.println("类路径"+clazzPath);

        //拆分方法名和(参数类型)返回值类型
        String methodName = methodName_types.split("\\(")[0];
        String types = methodName_types.split("\\(")[1];
//        System.out.println("方法名"+methodName);


        //拆分参数类型和返回值类型
        String paraType = types.split("\\)")[0];
        String returnType= types.split("\\)")[1];
//        System.out.println("参数类型"+paraType);
//        System.out.println("返回值类型"+returnType);

        //判断是否有多个参数
        String params[] = paraType.split(";");
        StringBuilder paraType_rectified = new StringBuilder();

        //有多个参数的情况
        if (params.length>1){
            for (int i = 0 ; i<params.length; i++){
                System.out.println(params[i]);
                if (i != params.length-1){
                    if (params[i].matches(regex3)){
                        paraType_rectified.append(params[i].substring(3)).append(",");
                    }else if(params[i].matches(regex2)) {
                        paraType_rectified.append(params[i].substring(2)).append(",");
                    }else if (params[i].startsWith("L") ||params[i].startsWith("D") || params[i].startsWith("I")) {
                        paraType_rectified.append(params[i].substring(1)).append(",");
                    }
                }else {
                    if (params[i].matches(regex3)){
                        paraType_rectified.append(params[i].substring(3));
                    }else if(params[i].matches(regex2)) {
                        paraType_rectified.append(params[i].substring(2));
                    }else if (params[i].startsWith("L") || params[i].startsWith("D") ||params[i].startsWith("I")) {
                        paraType_rectified.append(params[i].substring(1));
                    }
                }
            }
            if (paraType_rectified.toString().endsWith(","))
                paraType_rectified.delete(paraType_rectified.length()-1, paraType_rectified.length());
        }else { //只有一个参数或没有参数的情况
            System.out.println(paraType);
            //判断是否有参数
            if (paraType.length()>=2 && ! paraType.matches("^\\[[A-Z]$")){
                if (paraType.startsWith("[DL") ) {
                    paraType_rectified.append(paraType.substring(3, paraType.length() - 1).replace(";", ","));
                }else if (paraType.matches(regex2)) {
                    paraType_rectified.append(paraType.substring(2, paraType.length() - 1).replace(";", ","));
                }else if (paraType.startsWith("L") || paraType.startsWith("D") ||paraType.startsWith("I")) {
                    paraType_rectified.append(paraType.substring(1, paraType.length() - 1).replace(";", ","));
                }
            }

        }

        //拼接成正确的格式
//        System.out.println("修改后的参数类型"+paraType_rectified);

        result+=clazzPath+":" + methodName + "(" + paraType_rectified + ")";
//        System.out.println("修改后的方法"+result);
        return result;
    }

    public static Map<String, Set<String>> formatCallGraph(Map<String, Set<String>> callGraph) {
        if (callGraph == null || callGraph.isEmpty()) {
            return callGraph; // 如果为空直接返回
        }

        // 创建一个新的 Map 来存储格式化后的调用图
        Map<String, Set<String>> formattedCallGraph = new java.util.HashMap<>();

        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            // 格式化 key
            String formattedKey = PointFormator.format_Soot(entry.getKey());

            // 格式化 value 集合中的每个元素
            Set<String> formattedSet = new java.util.HashSet<>();
            for (String value : entry.getValue()) {
                formattedSet.add(PointFormator.format_Soot(value));
            }

            // 将格式化后的 key 和 value 存入新的 Map
            formattedCallGraph.put(formattedKey, formattedSet);
        }

        return formattedCallGraph;
    }

    public static void main(String[] args) {
        String testPoint = "org.deeplearning4j.earlystopping.saver.LocalFileGraphSaver:saveLatestModel(Lorg.deeplearning4j.nn.graph.ComputationGraph;)V";
        String s = format_Soot(testPoint);
        System.out.println(s);
    }
}
