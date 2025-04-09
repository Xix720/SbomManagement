package Utils;

import org.objectweb.asm.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;

import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

// 输入一个jar的路径，生成他的Map格式调用图
public class JarCallGraphBuilder_ASM {

    public static Map<String, Set<String>> generateJarCG(String jarPath) {
        Map<String, Set<String>> wholeCG = new HashMap<>();

        //遍历jar包中的class文件
        try (ZipFile zipFile = new ZipFile(jarPath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();

                // 检查是否为class文件
                if (entryName.endsWith(".class")) {
                    //如果是class文件则生成当前文件的调用图
                    FileSystem entryFileSystem = FileSystems.newFileSystem(Paths.get(jarPath), (ClassLoader) null);
                    Map<String, Set<String>> thisFileCG = processClassFile(entryFileSystem.getPath(entryName));
                    simplifyCallGraph(thisFileCG);
                    //合并调用图
                    wholeCG = mergeCG(wholeCG, thisFileCG);

                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return wholeCG;

    }

    public static Map<String, Set<String>> mergeCG(Map<String, Set<String>> CG1, Map<String, Set<String>> CG2){
        Map<String, Set<String>> result = new HashMap<>(CG1);

        for (Map.Entry<String, Set<String>> entry2 : CG2.entrySet()) {
            String key2 = entry2.getKey();
            Set<String> value2 = entry2.getValue();
            //若CG1中有这个key则直接合并
            if (CG1.containsKey(key2)){
                result.get(key2).addAll(value2);
            }else {
                //若没有则添加进CG1
                result.put(key2, value2);
            }
        }
        return result;
    }

    public static Map<String, Set<String>> processClassFile(Path filePath) {
        //当前class文件的调用图
        Map<String, Set<String>> classCG = new HashMap<>();

        try (InputStream inputStream = Files.newInputStream(filePath)) {
            ClassReader reader = new ClassReader(inputStream);
            ClassVisitor classVisitor = new ClassVisitor(Opcodes.ASM7) {
                private String className;

                @Override
                public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                    // Get the class name
                    className = name.replace('/', '.');
                }
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
                    MethodVisitor methodVisitor = super.visitMethod(access, name, desc, signature, exceptions);
                    //被调用方法的set
                    Set<String> calleeSet = new HashSet<>();

                    // Build call graph
                    String methodKey = (className + ":" + name + desc).replace('/', '.');
                    classCG.put(methodKey, calleeSet);

                    return new MethodVisitor(Opcodes.ASM7, methodVisitor) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
                            String calledClassName = owner.replace('/', '.');
                            String calledMethodKey = (calledClassName + ":" + name + desc).replace('/', '.');
                            calleeSet.add(calledMethodKey);
                            classCG.put(methodKey, calleeSet);
                            super.visitMethodInsn(opcode, owner, name, desc, itf);
                        }
                    };
                }
            };
            reader.accept(classVisitor, 0);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return classCG;
    }

    public static Set<String> extractMethods(Path classFilePath) throws IOException {
        Set<String> methods = new HashSet<>();

        try (InputStream inputStream = Files.newInputStream(classFilePath)) {
            ClassReader reader = new ClassReader(inputStream);
            ClassVisitor classVisitor = new ClassVisitor(Opcodes.ASM7) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
                    // Build the method signature and add it to the list
                    String methodSignature = name + desc;
                    methods.add(classFilePath.toString().split("\\.class")[0].replace("/",".") + ":" +methodSignature.replace("/","."));
                    return super.visitMethod(access, name, desc, signature, exceptions);
                }
            };
            reader.accept(classVisitor, 0);
        }
        return methods;
    }

    public static Map<String, Set<String>> simplifyCallGraph(Map<String, Set<String>> callGraphMap) {

        //移除核心包对其他包的调用
        callGraphMap.keySet().removeIf(caller ->caller.startsWith("java"));
        //移除jdk工具类的调用
        callGraphMap.keySet().removeIf(caller ->caller.startsWith("sun"));
        callGraphMap.keySet().removeIf(caller ->caller.startsWith("jdk"));

        for (Map.Entry<String, Set<String>> entry : callGraphMap.entrySet()) {
            String caller = entry.getKey();
            Set<String> callees = entry.getValue();
            // 移除对 Java 核心包的调用边
            callees.removeIf(callee -> callee.startsWith("java"));
            //移除对jdk工具类的调用边
            callees.removeIf(callee -> callee.startsWith("sun"));
            callees.removeIf(callee -> callee.startsWith("jdk"));
//            //移除组件对第三方组件的调用边
//            callees.removeIf(callee -> !callee.split("\\.")[0].equals(caller.split("\\.")[0]));

        }

        //过滤掉callee为空的caller
        callGraphMap.keySet().removeIf(caller ->callGraphMap.get(caller).size()==0);
        return callGraphMap;
    }
}
