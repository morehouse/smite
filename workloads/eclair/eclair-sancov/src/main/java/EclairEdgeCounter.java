import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

// Counts the total number of instrumentation probes across all instrumented
// packages (fr/acinq/, scala/, scodec/).
//
// Used at Docker build time to determine TARGET_MAP_SIZE for the smite scenario
// binary. Counts the same probes that EclairSanCov.prescan() assigns IDs to:
// one entry probe per non-abstract, non-native method, plus one probe per
// conditional branch fall-through and one per label/basic-block entry within
// each method.
//
// Usage: java -cp eclair-sancov.jar EclairEdgeCounter <jar1> [<jar2> ...]
//
// Prints the total probe count to stdout.
public class EclairEdgeCounter {

  static final String[] INSTRUMENTED_PREFIXES = {
      "fr/acinq/",
      "scala/",
      "scodec/",
  };

  static boolean shouldInstrument(String name) {
    for (String prefix : INSTRUMENTED_PREFIXES) {
      if (name.startsWith(prefix))
        return true;
    }
    return false;
  }

  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      System.err.println("Usage: EclairEdgeCounter <jar1> [<jar2> ...]");
      System.exit(1);
    }

    // probeCount[0] is used instead of a plain int because the anonymous
    // ClassVisitor requires any captured variable to be effectively final.
    int[] probeCount = {0};

    for (String jarPath : args) {
      if (!jarPath.endsWith(".jar")) {
        continue;
      }
      try (JarFile jar = new JarFile(jarPath)) {
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
          JarEntry je = entries.nextElement();
          String name = je.getName();
          if (!name.endsWith(".class") || !shouldInstrument(name)) {
            continue;
          }
          try (InputStream is = jar.getInputStream(je)) {
            byte[] bytecode = is.readAllBytes();
            ClassReader reader = new ClassReader(bytecode);
            reader.accept(
                new ClassVisitor(Opcodes.ASM9) {
                  @Override
                  public MethodVisitor visitMethod(
                      int access, String name, String descriptor,
                      String signature, String[] exceptions) {
                    if ((access & Opcodes.ACC_ABSTRACT) != 0 ||
                        (access & Opcodes.ACC_NATIVE) != 0) {
                      return null;
                    }
                    ++probeCount[0]; // entry probe
                    // Count body probes (conditional fall-throughs + labels).
                    return new MethodVisitor(Opcodes.ASM9) {
                      @Override
                      public void visitJumpInsn(int opcode, Label label) {
                        if (opcode != Opcodes.GOTO && opcode != Opcodes.JSR)
                          ++probeCount[0];
                      }

                      @Override
                      public void visitLabel(Label label) {
                        ++probeCount[0];
                      }
                    };
                  }
                },
                // SKIP_DEBUG suppresses line-number labels so only
                // branch-target and exception-handler labels appear in
                // visitLabel, matching the flags used in EclairTransformer and
                // prescan().
                ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
          }
        }
      } catch (Exception e) {
        throw new RuntimeException(
            "EclairEdgeCounter: failed to scan JAR: " + jarPath, e);
      }
    }

    System.out.println(probeCount[0]);
  }
}
