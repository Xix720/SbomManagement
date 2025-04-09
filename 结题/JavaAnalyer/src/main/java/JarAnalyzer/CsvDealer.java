package JarAnalyzer;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CsvDealer {

    public List<String> listExtractor(String csvFilePath, String columnName) {
        List<String> extractedList = new ArrayList<>();

        try (CSVReader reader = new CSVReader(new FileReader(csvFilePath))) {
            String[] headers = reader.readNext();

            if (headers == null) {
                throw new IOException("CSV file is empty");
            }

            int columnIndex = -1;
            for (int i = 0; i < headers.length; i++) {
                if (headers[i].equalsIgnoreCase(columnName)) {
                    columnIndex = i;
                    break;
                }
            }

            if (columnIndex == -1) {
                throw new IOException("Column not found: " + columnName);
            }

            String[] nextLine;
            while ((nextLine = reader.readNext()) != null) {
                if (nextLine.length > columnIndex) {
                    String columnValue = nextLine[columnIndex];

                    // 如果遇到分号就分开 记为两条数据
                    String[] valuesBeforeSemicolon = columnValue.split(";");
                    extractedList.addAll(Arrays.asList(valuesBeforeSemicolon));
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CsvValidationException e) {
            throw new RuntimeException(e);
        }

        return extractedList;
    }
    private static final Pattern CSV_PATTERN = Pattern.compile("\"([^\"]*)\"|([^,]+)|(,,)");

    // 原有的 filePath 版本
    public static Map<String, Set<String>> processCSV(String filePath, String column1, String column2) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(filePath)))) {
            return processCSV(br, column1, column2);
        } catch (IOException e) {
            e.printStackTrace();
            return Collections.emptyMap();
        }
    }

    // 新增的 InputStream 版本
    public static Map<String, Set<String>> processCSV(InputStream inputStream, String column1, String column2) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
            return processCSV(br, column1, column2);
        } catch (IOException e) {
            e.printStackTrace();
            return Collections.emptyMap();
        }
    }

    // 共享的解析逻辑
    private static Map<String, Set<String>> processCSV(BufferedReader br, String column1, String column2) throws IOException {
        Map<String, Set<String>> resultMap = new HashMap<>();

        // 读取CSV文件的头部
        String header = br.readLine();
        if (header == null) {
            throw new IllegalArgumentException("CSV文件为空");
        }

        String[] headers = header.split(",");
        int columnIndex1 = -1;
        int columnIndex2 = -1;

        // 获取列索引
        for (int i = 0; i < headers.length; i++) {
            if (headers[i].trim().equals(column1)) {
                columnIndex1 = i;
            } else if (headers[i].trim().equals(column2)) {
                columnIndex2 = i;
            }
        }

        // 检查是否找到指定列
        if (columnIndex1 == -1 || columnIndex2 == -1) {
            throw new IllegalArgumentException("指定的列名不存在");
        }

        // 逐行读取数据
        String line;
        while ((line = br.readLine()) != null) {
            Matcher matcher = CSV_PATTERN.matcher(line);

            String value1 = null;
            String value2 = null;
            int currentIndex = 0;

            while (matcher.find()) {
                String match = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);

                if (currentIndex == columnIndex1) {
                    value1 = match;
                } else if (currentIndex == columnIndex2) {
                    value2 = match;
                    break;  // 找到所需列后停止
                }
                currentIndex++;
            }

            // 处理第二列的分号拆分
            if (value1 != null && value2 != null) {
                Set<String> value2Set = new HashSet<>();
                String[] splitValues = value2.split(";");
                for (String splitValue : splitValues) {
                    value2Set.add(splitValue.trim());
                }
                resultMap.put(value1, value2Set);
            }
        }

        return resultMap;
    }
    public static Map<String, Set<String>> searchForKeyword(Map<String, Set<String>> originalMap, String keyword) {
        Map<String, Set<String>> resultMap = new HashMap<>();

        for (Map.Entry<String, Set<String>> entry : originalMap.entrySet()) {
            String key = entry.getKey();
            Set<String> values = entry.getValue();

            //查找CVE编号
            if (key.equals(keyword)){
                resultMap.put(key, values);
                break;
            }
        }

        return resultMap;
    }

    public static void main(String[] args) {
        // 示例用法
        String filePath = "src/main/CSVs/CVE.csv";
        String column1 = "CVE_ID";
        String column2 = "VUL_FUNs";

        Map<String, Set<String>> result = processCSV(filePath, column1, column2);
        Map<String, Set<String>> rrr = searchForKeyword(result, "CVE-2013-5823");

        // 打印结果
        for (Map.Entry<String, Set<String>> entry : rrr.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }


}
