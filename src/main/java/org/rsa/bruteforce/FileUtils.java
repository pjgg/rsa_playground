package org.rsa.bruteforce;

import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileUtils {

    public static String loadFile(File file) throws IOException {
        return org.apache.commons.io.FileUtils.readFileToString(file, StandardCharsets.UTF_8);
    }

    public static String loadFile(String file) throws IOException {
        return IOUtils.toString(
                FileUtils.class.getResourceAsStream(file),
                StandardCharsets.UTF_8);
    }

    public static Path copyContentTo(String content, Path target) throws IOException {
        Files.writeString(target, content);
        return target;
    }

    public static Path getResourcePath(String fileName) {
        return Path.of(FileUtils.class.getResource(fileName).getPath());
    }
}
