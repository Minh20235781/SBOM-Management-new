package com.example.sbom.service.reconciliation;

import com.example.sbom.dto.reconciliation.RuntimePackageItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;

import java.lang.reflect.Field;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bộ quét Runtime dựa trên Java Reflection & JVM ClassLoader.
 * Khám phá các thư viện và package thực tế đang nạp trong bộ nhớ RAM của ứng dụng.
 */
@Service
public class JavaReflectionRuntimeInspector {

    private static final Logger log = LoggerFactory.getLogger(JavaReflectionRuntimeInspector.class);

    // Regex bóc tách tên thư viện và version từ file jar: mysql-connector-j-8.3.0.jar -> (mysql-connector-j, 8.3.0)
    private static final Pattern JAR_PATTERN = Pattern.compile("^(.*?)-(\\d+(\\.[\\w\\-\\.]+)?)\\.jar$");

    @Autowired(required = false)
    private ApplicationContext applicationContext;

    /**
     * Quét toàn diện các thư viện đang nạp trong JVM bằng Reflection và Spring Bean Introspection
     */
    public List<RuntimePackageItem> inspectCurrentJvm() {
        Map<String, JarStats> jarMap = new LinkedHashMap<>();
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // Chiến lược 1: Dùng Reflection duyệt qua tất cả Spring Beans đang hoạt động trong RAM
        inspectSpringBeansViaReflection(jarMap);

        // Chiến lược 2: Dùng Reflection kiểm tra ClassLoader.classes (nếu JVM cho phép)
        inspectClassLoaderViaReflection(jarMap);

        // Chiến lược 3: Quét qua Package.getPackages() của JVM
        inspectJvmPackages(jarMap);

        List<RuntimePackageItem> result = new ArrayList<>();
        for (JarStats stats : jarMap.values()) {
            result.add(RuntimePackageItem.builder()
                    .name(stats.name)
                    .version(stats.version)
                    .loadedClassesCount(stats.classCount)
                    .loadedAt(timestamp)
                    .source(stats.source)
                    .build());
        }

        // Sắp xếp theo số lượng class nạp nhiều nhất lên đầu
        result.sort((a, b) -> Integer.compare(
                b.getLoadedClassesCount() != null ? b.getLoadedClassesCount() : 0,
                a.getLoadedClassesCount() != null ? a.getLoadedClassesCount() : 0
        ));

        log.info("Java Reflection quét được {} thư viện/package thực sự đang chạy trong RAM JVM", result.size());
        return result;
    }

    /**
     * Dùng Reflection quét tất cả Beans trong ApplicationContext và truy vết CodeSource của class
     */
    private void inspectSpringBeansViaReflection(Map<String, JarStats> jarMap) {
        if (applicationContext == null) return;
        try {
            String[] beanNames = applicationContext.getBeanDefinitionNames();
            for (String beanName : beanNames) {
                try {
                    Object bean = applicationContext.getBean(beanName);
                    Class<?> clazz = bean.getClass();

                    // Xử lý CGLIB proxy nếu có
                    if (clazz.getName().contains("$$")) {
                        clazz = clazz.getSuperclass();
                    }

                    inspectClassCodeSource(clazz, jarMap, "SPRING_BEAN_REFLECTION");
                } catch (Exception ignored) {
                    // Bỏ qua bean lazy hoặc scope không khả dụng
                }
            }
        } catch (Exception ex) {
            log.warn("Lỗi khi quét Beans qua Reflection: {}", ex.getMessage());
        }
    }

    /**
     * Dùng Reflection trích xuất trường ẩn 'classes' trong ClassLoader
     */
    @SuppressWarnings("unchecked")
    private void inspectClassLoaderViaReflection(Map<String, JarStats> jarMap) {
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            while (cl != null) {
                try {
                    Field f = ClassLoader.class.getDeclaredField("classes");
                    f.setAccessible(true);
                    Vector<Class<?>> classes = (Vector<Class<?>>) f.get(cl);
                    if (classes != null) {
                        List<Class<?>> snapshot = new ArrayList<>(classes);
                        for (Class<?> clazz : snapshot) {
                            inspectClassCodeSource(clazz, jarMap, "JVM_CLASSLOADER_REFLECTION");
                        }
                    }
                } catch (Exception ignored) {
                    // Java 17+ có thể chặn setAccessible nếu thiếu --add-opens, fallback an toàn
                }
                cl = cl.getParent();
            }
        } catch (Exception ex) {
            log.debug("Fallback ClassLoader reflection: {}", ex.getMessage());
        }
    }

    /**
     * Quét Package.getPackages() của JVM
     */
    private void inspectJvmPackages(Map<String, JarStats> jarMap) {
        try {
            for (Package p : Package.getPackages()) {
                String title = p.getImplementationTitle();
                String ver = p.getImplementationVersion();
                if (title != null && ver != null && !title.isBlank()) {
                    String cleanName = title.trim();
                    if (!jarMap.containsKey(cleanName.toLowerCase(Locale.ROOT))) {
                        jarMap.put(cleanName.toLowerCase(Locale.ROOT),
                                new JarStats(cleanName, ver, 1, "JVM_PACKAGE_REGISTRY"));
                    }
                }
            }
        } catch (Exception ex) {
            log.debug("Lỗi đọc Package registry: {}", ex.getMessage());
        }
    }

    private void inspectClassCodeSource(Class<?> clazz, Map<String, JarStats> jarMap, String sourceTag) {
        try {
            ProtectionDomain pd = clazz.getProtectionDomain();
            if (pd == null) return;
            CodeSource cs = pd.getCodeSource();
            if (cs == null || cs.getLocation() == null) return;

            URL location = cs.getLocation();
            String path = location.getPath();
            if (path == null) return;

            if (path.endsWith(".jar") || path.contains(".jar!")) {
                String jarFileName = path.substring(path.lastIndexOf('/') + 1).replace("!/", "");
                parseAndAggregateJar(jarFileName, jarMap, sourceTag);
            }
        } catch (Exception ignored) {
        }
    }

    private void parseAndAggregateJar(String jarFileName, Map<String, JarStats> jarMap, String sourceTag) {
        Matcher m = JAR_PATTERN.matcher(jarFileName);
        String name;
        String version;

        if (m.matches()) {
            name = m.group(1);
            version = m.group(2);
        } else {
            name = jarFileName.replace(".jar", "");
            version = "embedded";
        }

        String key = name.toLowerCase(Locale.ROOT);
        JarStats stats = jarMap.get(key);
        if (stats == null) {
            jarMap.put(key, new JarStats(name, version, 1, sourceTag));
        } else {
            stats.classCount++;
        }
    }

    private static class JarStats {
        String name;
        String version;
        int classCount;
        String source;

        JarStats(String name, String version, int classCount, String source) {
            this.name = name;
            this.version = version;
            this.classCount = classCount;
            this.source = source;
        }
    }
}
