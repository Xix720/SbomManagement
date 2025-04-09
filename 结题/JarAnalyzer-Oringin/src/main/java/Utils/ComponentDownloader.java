package Utils;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

public class ComponentDownloader {

    public static void main(String[] args) {
        // 示例输入：groupId:artifactId:version
        String input = "org.apache.logging.log4j:log4j-core:2.13.3";
        String targetFolder = "src/main/Jars-CVE";  // 你的目标文件夹路径
        downloadComponent(input, targetFolder);
    }

    public static String downloadComponent(String gav, String targetFolder) {
        String jarFile = "";
        try {
            // 解析输入的 G:A:V 变量
            String[] parts = gav.split(":");
            if (parts.length != 3) {
                System.out.println("输入格式错误，正确格式为 GroupId:ArtificialId:Version");
                System.out.println("示例：org.apache.logging.log4j:log4j-core:2.13.3");
                return null;
            }

            String groupId = parts[0];
            String artifactId = parts[1];
            String version = parts[2];


            // 构建Maven坐标URL
            String mavenURL = "https://repo.maven.apache.org/maven2/" +
                    groupId.replace('.', '/') + "/" +
                    artifactId + "/" +
                    version + "/" +
                    artifactId + "-" + version + ".jar";
            // 构建完整的目标文件路径
            Path targetFilePath = Paths.get(targetFolder, artifactId + "-" + version + ".jar");

            // 判断文件是否已存在
            if (Files.exists(targetFilePath)) {
                System.out.println("组件已存在：" + targetFilePath);
                jarFile = targetFilePath.toString();
            } else {
                // 下载组件到目标文件夹
                jarFile = downloadFile(mavenURL, targetFolder, artifactId + "-" + version + ".jar");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return jarFile;
    }

    private static String downloadFile(String urlString, String targetFolder, String fileName) throws IOException {
        URL url = new URL(urlString);
        URLConnection connection = url.openConnection();

        // 确保目标文件夹存在
        Path targetPath = Paths.get(targetFolder);
        if (!Files.exists(targetPath)) {
            Files.createDirectories(targetPath);
        }

        // 构建完整的目标文件路径
        Path targetFilePath = targetPath.resolve(fileName);

        // 下载组件到目标文件夹
        try (InputStream in = connection.getInputStream()) {
            Files.copy(in, targetFilePath, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("组件下载成功：" + targetFilePath);
        } catch (IOException e) {
            System.out.println("组件下载失败：" + e.getMessage());
        }
        return targetFilePath.toString();
    }
}
