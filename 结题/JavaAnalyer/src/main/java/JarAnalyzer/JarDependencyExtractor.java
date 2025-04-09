package JarAnalyzer;

import org.objectweb.asm.*;
import org.objectweb.asm.ClassReader;

import java.io.*;
import java.util.*;
import java.util.jar.*;


public class JarDependencyExtractor {

    private static final List<String> CORE_PACKAGES = Arrays.asList(
            "java.", "javax.", "jdk.", "sun.", "com.sun."
    );

    public static Set<String> extractThirdPartyDependencies(String jarPath) throws IOException {
        Set<String> dependencies = new HashSet<>();
        Set<String> internalClasses = new HashSet<>();

        try (JarFile jarFile = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jarFile.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    try (InputStream input = jarFile.getInputStream(entry)) {
                        ClassReader classReader = new ClassReader(input);
                        ClassDependencyVisitor visitor = new ClassDependencyVisitor(internalClasses, dependencies);
                        classReader.accept(visitor, ClassReader.SKIP_DEBUG);
                    }
                }
            }
        }

        // 过滤掉 JDK 类、JAR 内部类以及基础库
        dependencies.removeIf(cls -> isCoreLibrary(cls) || internalClasses.contains(cls));

        return dependencies;
    }
    private static boolean isCoreLibrary(String className) {
        for (String prefix : CORE_PACKAGES) {
            if (className.contains(prefix)) {
                return true;
            }
        }
        return false;
    }

    static class ClassDependencyVisitor extends ClassVisitor {
        private final Set<String> internalClasses;
        private final Set<String> dependencies;
        private String currentClassName;

        public ClassDependencyVisitor(Set<String> internalClasses, Set<String> dependencies) {
            super(Opcodes.ASM9);
            this.internalClasses = internalClasses;
            this.dependencies = dependencies;
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            currentClassName = name.replace('/', '.');
            internalClasses.add(currentClassName);
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
                dependencies.add(type.replace('/', '.'));
                super.visitTypeInsn(opcode, type);
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                dependencies.add(owner.replace('/', '.'));
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            }
        }

        private void addDependencyFromDescriptor(String descriptor) {
            if (descriptor != null) {
                Type type = Type.getType(descriptor);
                if (type.getSort() == Type.OBJECT) {
                    dependencies.add(type.getClassName());
                }
            }
        }
    }

    public static void main(String[] args) throws IOException {
//
        String jarGAV= "org.deeplearning4j:deeplearning4j-core:0.4-rc1";
        String jarPath = ComponentDownloader.downloadComponent(jarGAV, "src/main/java/Jars");
        Set<String> thirdPartyDependencies = extractThirdPartyDependencies(jarPath);
        System.out.println("Third-party dependencies found:");
        thirdPartyDependencies.stream().map(PointFormator::format_Soot).filter(s -> !s.equals("null")).forEach(System.out::println);
    }
}
