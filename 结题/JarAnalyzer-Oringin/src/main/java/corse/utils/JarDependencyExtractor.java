package corse.utils;

import Utils.ComponentDownloader;
import Utils.PointFormator;
import org.objectweb.asm.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

public class JarDependencyExtractor {

    private static final List<String> CORE_PACKAGES = Arrays.asList(
            "java.", "javax.", "jdk.", "sun.", "com.sun."
    );

    /**
     * 提取 JAR 包中的调用关系图
     * @param jarPath JAR 文件路径
     * @return Map<String, Set<String>>，表示类调用关系
     * @throws IOException 解析 JAR 失败
     */
    public static Map<String, Set<String>> extractDependencyGraph(String jarPath) throws IOException {
        Map<String, Set<String>> dependencyGraph = new HashMap<>();
        Set<String> internalClasses = new HashSet<>();

        try (JarFile jarFile = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jarFile.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    try (InputStream input = jarFile.getInputStream(entry)) {
                        ClassReader classReader = new ClassReader(input);
                        ClassDependencyVisitor visitor = new ClassDependencyVisitor(internalClasses, dependencyGraph);
                        classReader.accept(visitor, ClassReader.SKIP_DEBUG);
                    }
                }
            }
        }

        // 过滤掉 JDK 类和 JAR 内部类
        dependencyGraph.forEach((caller, callees) ->
                callees.removeIf(cls -> isCoreLibrary(cls) || internalClasses.equals(cls))
        );

        return dependencyGraph;
    }

    private static boolean isCoreLibrary(String className) {
        for (String prefix : CORE_PACKAGES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    static class ClassDependencyVisitor extends ClassVisitor {
        private final Set<String> internalClasses;
        private final Map<String, Set<String>> dependencyGraph;
        private String currentClassName;

        public ClassDependencyVisitor(Set<String> internalClasses, Map<String, Set<String>> dependencyGraph) {
            super(Opcodes.ASM9);
            this.internalClasses = internalClasses;
            this.dependencyGraph = dependencyGraph;
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            currentClassName = name.replace('/', '.');
            internalClasses.add(currentClassName);
            dependencyGraph.putIfAbsent(currentClassName, new HashSet<>());
            super.visit(version, access, name, signature, superName, interfaces);
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
            addDependencyFromDescriptor(descriptor);
            return super.visitField(access, name, descriptor, signature, value);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            addDependencyFromDescriptor(descriptor);
            return new MethodDependencyVisitor();
        }

        class MethodDependencyVisitor extends MethodVisitor {
            public MethodDependencyVisitor() {
                super(Opcodes.ASM9);
            }

            @Override
            public void visitTypeInsn(int opcode, String type) {
                addDependency(type);
                super.visitTypeInsn(opcode, type);
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                addDependency(owner);
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            }
        }

        private void addDependencyFromDescriptor(String descriptor) {
            if (descriptor != null) {
                Type type = Type.getType(descriptor);
                if (type.getSort() == Type.OBJECT) {
                    addDependency(type.getClassName());
                }
            }
        }

        private void addDependency(String className) {
            if (!isCoreLibrary(className)) {
                dependencyGraph.get(currentClassName).add(className.replace('/', '.'));
            }
        }
    }

    public static void main(String[] args) throws IOException {
        String jarGAV= "org.deeplearning4j:deeplearning4j-core:0.4-rc1";
        String jarPath = ComponentDownloader.downloadComponent(jarGAV, "src/main/java/Jars");
        Map<String, Set<String>> dependencyGraph = extractDependencyGraph(jarPath);


    }
}