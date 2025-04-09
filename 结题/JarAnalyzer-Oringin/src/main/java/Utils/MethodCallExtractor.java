package Utils;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class MethodCallExtractor {

    public static void main(String[] args) throws IOException {
        // 读取编译后的.class文件
        InputStream inputStream = MethodCallExtractor.class.getResourceAsStream("AsianFontMapper.class");
        ClassReader reader = new ClassReader(inputStream);

        // 创建Visitor来访问类和方法
        MethodCallVisitor visitor = new MethodCallVisitor();
        reader.accept(visitor, 0);

        // 输出方法调用涉及到的其他类和方法
        for (Map.Entry<String, String> entry : visitor.getMethodCalls().entrySet()) {
            System.out.println("Method: " + entry.getKey());
            System.out.println("Calls: " + entry.getValue());
        }
    }

    // Visitor类，用于访问类和方法，并分析方法调用
    private static class MethodCallVisitor extends ClassVisitor {
        // 存储方法调用涉及到的其他类和方法
        private Map<String, String> methodCalls = new HashMap<>();
        private String currentMethod;

        public MethodCallVisitor() {
            super(Opcodes.ASM8);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            currentMethod = name;
            return new MethodVisitor(Opcodes.ASM8) {
                @Override
                public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                    // 记录方法调用涉及到的其他类和方法
                    methodCalls.put(currentMethod, owner + "." + name);
                }
            };
        }

        public Map<String, String> getMethodCalls() {
            return methodCalls;
        }
    }
}
