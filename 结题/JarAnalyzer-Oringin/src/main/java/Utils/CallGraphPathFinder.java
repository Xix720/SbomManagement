package Utils;

import java.util.*;

public class CallGraphPathFinder {

    public static List<String> findPath(Map<String, Set<String>> callGraph, String source, String target) {
        List<String> path = new ArrayList<>();
        Set<String> visited = new HashSet<>();

        if (dfs(callGraph, source, target, visited, path)) {
            // Reverse the path to get the correct order
            Collections.reverse(path);
            return path;
        } else {
            return Collections.emptyList(); // Return an empty list if no path is found
        }
    }

    private static boolean dfs(Map<String, Set<String>> callGraph, String current, String target, Set<String> visited, List<String> path) {
        path.add(current);

        if (current.equals(target)) {
            return true;
        }

        visited.add(current);

        Set<String> neighbors = callGraph.getOrDefault(current, Collections.emptySet());

        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor) && dfs(callGraph, neighbor, target, visited, path)) {
                return true;
            }
        }

        // If the current path does not lead to the target, backtrack
        path.remove(path.size() - 1);

        return false;
    }

    public static void main(String[] args) {
        Map<String, Set<String>> callGraph = new HashMap<>();
        callGraph.put("MethodA", new HashSet<>(Arrays.asList("MethodB", "MethodC")));
        callGraph.put("MethodB", new HashSet<>(Collections.singletonList("MethodD")));
        callGraph.put("MethodC", new HashSet<>(Collections.singletonList("MethodD")));
        callGraph.put("MethodD", new HashSet<>(Collections.singletonList("MethodE")));
        callGraph.put("MethodF", new HashSet<>(Collections.singletonList("MethodG")));

        String sourceMethod = "MethodA";
        String targetMethod = "MethodA";

        List<String> path = findPath(callGraph, sourceMethod, targetMethod);

        if (!path.isEmpty()) {
            System.out.println("找到从 " + sourceMethod + " 到 " + targetMethod + " 的路径:");
            System.out.println(String.join(" -> ", path));
        } else {
            System.out.println("未找到从 " + sourceMethod + " 到 " + targetMethod + " 的路径");
        }
    }
}
