package JarAnalyzer;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;

import java.io.File;
import java.util.*;

// 输入一个Java项目的路径，生成它的Map格式调用图
public class JavaCallGraphBuilder {
    private static final Set<String> standardLibraryClasses = new HashSet<>(Arrays.asList(
            "String", "Math", "System", "Object", "Integer", "Long", "Double", "Float", "Character", "Boolean", "Short", "Byte", "Thread", "Throwable"
    ));

    public static Map<String, Set<String>> generateJavaCG(String sourceDirPath) {
        Map<String, Set<String>> wholeCG = new HashMap<>();
        File sourceDir = new File(sourceDirPath);

        // 遍历目录下的所有.java文件
        if (sourceDir.isDirectory()) {
            List<File> javaFiles = listJavaFiles(sourceDir);

            for (File javaFile : javaFiles) {
                System.out.println("正在生成调用图：" + javaFile.getName());
                // 解析每个.java文件并生成调用图
                Map<String, Set<String>> thisFileCG = processJavaFile(javaFile);
                if (thisFileCG == null)
                    continue;
                simplifyCallGraph(thisFileCG);
                // 合并调用图
                wholeCG = mergeCG(wholeCG, thisFileCG);
            }
        }
        return wholeCG;
    }

    // 列出目录下所有的.java文件
    public static List<File> listJavaFiles(File dir) {
        List<File> javaFiles = new ArrayList<>();
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    javaFiles.addAll(listJavaFiles(file)); // 递归处理子目录
                } else if (file.getName().endsWith(".java")) {
                    javaFiles.add(file);
                }
            }
        }
        return javaFiles;
    }

    // 解析Java文件并生成调用图
    public static Map<String, Set<String>> processJavaFile(File javaFile) {
        Map<String, Set<String>> classCG = new HashMap<>();

        try {
            CompilationUnit cu = StaticJavaParser.parse(javaFile);
            String packageName = cu.getPackageDeclaration()
                    .map(pd -> pd.getName().toString())
                    .orElse("");

            cu.findAll(ClassOrInterfaceDeclaration.class).forEach(classOrInterface -> {
                String className = packageName.isEmpty() ? classOrInterface.getNameAsString() : packageName + "." + classOrInterface.getNameAsString();
                classOrInterface.findAll(MethodDeclaration.class).forEach(method -> {
                    String methodName = className + ":" + method.getNameAsString();
                    Set<String> calleeSet = new HashSet<>();

                    method.findAll(MethodCallExpr.class).forEach(methodCall -> {
                        String calledClass = methodCall.getScope()
                                .map(scope -> scope.toString())
                                .orElse(className);

                        // 如果调用的类是标准库类，则跳过该调用
                        if (isStandardLibraryClass(calledClass)) {
                            return;
                        }

                        // 确保调用的类路径正确
                        if (!calledClass.contains(".")) {
                            calledClass = className;
                        }

                        String calledMethod = calledClass + ":" + methodCall.getNameAsString();
                        calleeSet.add(calledMethod);
                    });

                    classCG.put(methodName, calleeSet);
                });
            });
        } catch (Exception e) {
            return null;
        }

        return classCG;
    }
    private static boolean isStandardLibraryClass(String className) {
        // 检查类名是否属于Java标准库的常用类
        return standardLibraryClasses.contains(className) || className.startsWith("java.") || className.startsWith("javax.");
    }

    // 合并调用图
    public static Map<String, Set<String>> mergeCG(Map<String, Set<String>> CG1, Map<String, Set<String>> CG2) {
        Map<String, Set<String>> result = new HashMap<>(CG1);

        for (Map.Entry<String, Set<String>> entry2 : CG2.entrySet()) {
            String key2 = entry2.getKey();
            Set<String> value2 = entry2.getValue();
            // 若CG1中有这个key则直接合并
            if (CG1.containsKey(key2)) {
                result.get(key2).addAll(value2);
            } else {
                // 若没有则添加进CG1
                result.put(key2, value2);
            }
        }
        return result;
    }

    // 简化调用图，移除对Java核心类和库的调用
    public static Map<String, Set<String>> simplifyCallGraph(Map<String, Set<String>> callGraphMap) {
        callGraphMap.keySet().removeIf(caller -> caller.startsWith("java"));
        callGraphMap.keySet().removeIf(caller -> caller.startsWith("javax"));
        callGraphMap.keySet().removeIf(caller -> caller.startsWith("sun"));
        callGraphMap.keySet().removeIf(caller -> caller.contains("("));

        for (Map.Entry<String, Set<String>> entry : callGraphMap.entrySet()) {
            Set<String> callees = entry.getValue();
            callees.removeIf(callee -> callee.startsWith("java"));
            callees.removeIf(callee -> callee.startsWith("javax"));
            callees.removeIf(callee -> callee.startsWith("sun"));
            callees.removeIf(callee -> callee.contains("("));
        }

        // 过滤掉没有调用任何方法的条目
        callGraphMap.keySet().removeIf(caller -> callGraphMap.get(caller).isEmpty());
        return callGraphMap;
    }
}
