import java.io.File;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.ByteBuffer;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

// Java agent that provides AFL coverage feedback for Eclair.
//
// When loaded via -javaagent:eclair-sancov.jar, this agent maps the AFL shared
// memory region and instruments classes to record basic-block-level coverage.
// Each instrumented method receives:
//   - One probe at method entry
//   - One probe after each conditional jump (fall-through arc)
//   - One probe at each label / basic-block entry (taken arc)
//
// Instrumented packages:
//   - fr/acinq/  (Eclair, bitcoin-lib, secp256k1)
//   - scala/     (collections, Option, pattern matching runtime)
//   - scodec/    (binary codec used for BOLT wire message serialization)
//
// Edge IDs are pre-assigned by scanning all JARs on the classpath before any
// class is loaded, sorted by class name then declaration order within each
// class. This gives stable IDs across restarts, which is required for afl-cmin
// and cross-session coverage comparisons to work correctly.
public class EclairSanCov {

  // Map from "InternalClassName#methodName#descriptor" to pre-assigned edge ID.
  // Populated by prescan() before any class transformation occurs.
  static Map<String, Integer> edgeIds = null;

  // Map from class name to superclass name, built from all classes on the
  // classpath during prescan. Used by NonLoadingClassWriter to resolve type
  // hierarchies without Class.forName().
  static Map<String, String> superclassMap = null;

  // Direct ByteBuffer pointing at the AFL shared memory region.
  static volatile ByteBuffer shmBuffer = null;

  // Java agent entry point, called by the JVM before main().
  public static void premain(String args, Instrumentation inst) {
    String shmIdStr = System.getenv("__AFL_SHM_ID");
    if (shmIdStr == null) {
      throw new RuntimeException("eclair-sancov: __AFL_SHM_ID not set");
    }

    edgeIds = prescan();

    System.loadLibrary("eclair-sancov");
    shmBuffer = mapShm(Integer.parseInt(shmIdStr));

    inst.addTransformer(new EclairTransformer());
  }

  // Maps the AFL shared memory segment via shmat and wraps it as a direct
  // ByteBuffer. The buffer capacity equals AFL_MAP_SIZE (set in the environment
  // by the nyx-agent before spawning Eclair). Implemented in shmutil.c via JNI.
  private static native ByteBuffer mapShm(int shmId);

  // Records coverage for an instrumented probe. Called from every instrumented
  // coverage point. edgeId is a pre-assigned sequential integer always in
  // [0, AFL_MAP_SIZE).
  public static void edge(int edgeId) {
    shmBuffer.put(edgeId, (byte)(shmBuffer.get(edgeId) + 1));
  }

  // Package prefixes to instrument. A class is instrumented if its internal
  // name starts with any of these prefixes.
  static final String[] INSTRUMENTED_PREFIXES = {
      "fr/acinq/", // Eclair, bitcoin-lib, secp256k1-kmp
      "scala/",    // collections, Option, pattern matching runtime
      "scodec/",   // binary codec for BOLT wire message serialization
  };

  static boolean shouldInstrument(String className) {
    for (String prefix : INSTRUMENTED_PREFIXES) {
      if (className.startsWith(prefix))
        return true;
    }
    return false;
  }

  // Scans all JARs on the classpath and assigns sequential probe IDs to every
  // non-abstract, non-native method in instrumented classes. Each method
  // receives one ID for its entry probe plus one ID per body probe (conditional
  // fall-throughs and label/basic-block entries). Classes are processed in
  // sorted order by internal name; methods and their instructions are processed
  // in declaration/bytecode order (as visited by ASM). This gives deterministic
  // IDs independent of class loading order at runtime.
  static Map<String, Integer> prescan() {
    // Collect the set of JAR files to scan. java.class.path contains the
    // explicit -cp arguments, which may include JAR files and directories.
    List<String> jarPaths = new ArrayList<>();
    String classpath = System.getProperty("java.class.path", "");
    for (String entry : classpath.split(":")) {
      if (entry.endsWith(".jar")) {
        jarPaths.add(entry);
      } else {
        File dir = new File(entry);
        if (dir.isDirectory()) {
          File[] jars = dir.listFiles(f -> f.getName().endsWith(".jar"));
          if (jars != null) {
            for (File jar : jars) {
              jarPaths.add(jar.getAbsolutePath());
            }
          }
        }
      }
    }

    // Scan all classes in all JARs. Instrumented classes go into sortedClasses
    // for probe ID assignment; all classes contribute to superclassMap for
    // type hierarchy resolution.
    TreeMap<String, byte[]> sortedClasses = new TreeMap<>();
    superclassMap = new HashMap<>();

    for (String entry : jarPaths) {
      try (JarFile jar = new JarFile(entry)) {
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
          JarEntry je = entries.nextElement();
          String name = je.getName();
          if (!name.endsWith(".class")) {
            continue;
          }
          String className =
              name.substring(0, name.length() - 6); // strip .class
          try (InputStream is = jar.getInputStream(je)) {
            byte[] bytecode = is.readAllBytes();
            // Record superclass for every class on the classpath.
            ClassReader cr = new ClassReader(bytecode);
            String superName = cr.getSuperName();
            if (superName != null) {
              superclassMap.put(className, superName);
            }
            if (shouldInstrument(name)) {
              sortedClasses.put(className, bytecode);
            }
          }
        }
      } catch (Exception e) {
        throw new RuntimeException(
            "eclair-sancov: failed to scan JAR: " + entry, e);
      }
    }

    // Assign sequential IDs by visiting each class in sorted order. counter[0]
    // is used instead of a plain int because the anonymous ClassVisitor
    // requires any captured variable to be effectively final.
    Map<String, Integer> ids = new HashMap<>();
    int[] counter = {0};

    for (Map.Entry<String, byte[]> entry : sortedClasses.entrySet()) {
      String className = entry.getKey();
      byte[] bytecode = entry.getValue();

      ClassReader reader = new ClassReader(bytecode);
      reader.accept(
          new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(
                int access, String name, String descriptor, String signature,
                String[] exceptions) {
              if ((access & Opcodes.ACC_ABSTRACT) != 0 ||
                  (access & Opcodes.ACC_NATIVE) != 0) {
                return null;
              }
              // We include the descriptor in the key because overloaded methods
              // share the same name. The descriptor encodes the parameter and
              // return types (e.g. "(I)V" = takes int, returns void), making it
              // unique per overload.
              String key = className + "#" + name + "#" + descriptor;
              ids.put(key, counter[0]++); // entry probe ID
              // Count body probes to reserve their IDs after the entry probe:
              // one per conditional fall-through, one per label/basic-block
              // entry.
              return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitJumpInsn(int opcode, Label label) {
                  if (opcode != Opcodes.GOTO && opcode != Opcodes.JSR)
                    ++counter[0]; // fall-through arc probe
                }

                @Override
                public void visitLabel(Label label) {
                  ++counter[0]; // basic block entry probe
                }
              };
            }
          },
          // SKIP_DEBUG suppresses line-number labels so only branch-target and
          // exception-handler labels appear in visitLabel, matching the flags
          // used in EclairTransformer.
          ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }

    return ids;
  }

  // ASM ClassFileTransformer that instruments every non-abstract, non-native
  // method in instrumented classes with edge() probes at the method entry, each
  // conditional branch fall-through, and each basic-block entry label.
  static class EclairTransformer implements ClassFileTransformer {

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {

      if (className == null || !shouldInstrument(className)) {
        return null; // null = no transformation
      }

      try {
        ClassReader reader = new ClassReader(classfileBuffer);
        // COMPUTE_FRAMES tells ASM to recompute stack map frames from scratch
        // after transformation (inserting INVOKESTATIC probes changes stack
        // depth). SKIP_DEBUG | SKIP_FRAMES must match the prescan() flags so
        // both passes see the same label set and probe counts agree.
        ClassWriter writer =
            new NonLoadingClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
        reader.accept(new EclairClassVisitor(writer, className),
                      ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return writer.toByteArray();
      } catch (Throwable e) {
        System.err.println("eclair-sancov: transform failed for " + className +
                           ": " + e);
        return null;
      }
    }
  }

  // Returns the superclass of an internal class name. Checks superclassMap
  // (classpath JARs) first, then falls back to Class.forName() for JDK classes
  // not present in those JARs. The fallback is safe because JDK classes don't
  // match INSTRUMENTED_PREFIXES, so the transformer returns null immediately
  // for them -- no recursive transformation, no ClassCircularityError.
  static String superOf(String type) {
    String s = superclassMap.get(type);
    if (s != null)
      return s;
    try {
      Class<?> c = Class.forName(type.replace('/', '.'), false, null);
      Class<?> p = c.getSuperclass();
      return p != null ? p.getName().replace('.', '/') : null;
    } catch (Exception e) {
      return null;
    }
  }

  // ClassWriter that resolves type hierarchies via superclassMap instead of
  // the default Class.forName(). The default getCommonSuperClass() triggers
  // class loading, which causes ClassCircularityError in deep hierarchies like
  // scala/collection/ where transforming class A requires loading class B and
  // vice versa.
  static class NonLoadingClassWriter extends ClassWriter {

    NonLoadingClassWriter(ClassReader reader, int flags) {
      super(reader, flags);
    }

    @Override
    protected String getCommonSuperClass(String type1, String type2) {
      java.util.Set<String> ancestors = new java.util.HashSet<>();
      for (String t = type1; t != null && ancestors.add(t); t = superOf(t))
        ;
      for (String t = type2; t != null; t = superOf(t))
        if (ancestors.contains(t))
          return t;
      return "java/lang/Object";
    }
  }

  static class EclairClassVisitor extends ClassVisitor {

    private final String className;

    EclairClassVisitor(ClassVisitor cv, String className) {
      super(Opcodes.ASM9, cv);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {

      MethodVisitor mv =
          super.visitMethod(access, name, descriptor, signature, exceptions);

      if ((access & Opcodes.ACC_ABSTRACT) != 0 ||
          (access & Opcodes.ACC_NATIVE) != 0) {
        return mv;
      }

      String key = className + "#" + name + "#" + descriptor;
      Integer edgeId = EclairSanCov.edgeIds.get(key);
      if (edgeId == null) {
        // Class was not found in the prescan (e.g. dynamically generated at
        // runtime). Scala closures compiled into JARs are picked up by the
        // prescan; true runtime-generated classes (e.g. reflection proxies)
        // typically have non-Eclair names and are excluded by the prefix filter
        // before reaching here.
        return mv;
      }

      return new EclairMethodVisitor(mv, edgeId);
    }
  }

  // Instruments a single method with edge() probes at:
  //   - Method entry
  //   - After each conditional jump (fall-through arc)
  //   - After each label (basic-block entry: covers all taken arcs, loop
  //     headers, switch cases, exception handlers, and merge points)
  //
  // Probe IDs are allocated starting at edgeId (entry) then edgeId+1,
  // edgeId+2, ... for body probes in instruction-visit order. prescan() uses
  // the same visit order and flags to reserve the correct number of IDs per
  // method, guaranteeing stable, non-overlapping IDs across restarts.
  static class EclairMethodVisitor extends MethodVisitor {

    private int currentProbeId;

    EclairMethodVisitor(MethodVisitor mv, int edgeId) {
      super(Opcodes.ASM9, mv);
      currentProbeId = edgeId;
    }

    // Emits: ldc probeId; invokestatic EclairSanCov.edge(I)V
    private void emitProbe() {
      super.visitLdcInsn(currentProbeId++);
      super.visitMethodInsn(Opcodes.INVOKESTATIC, "EclairSanCov", "edge",
                            "(I)V", false);
    }

    @Override
    public void visitCode() {
      // visitCode() opens the Code attribute and must be called first. The
      // probe inserted after it fires at method entry.
      super.visitCode();
      emitProbe();
    }

    // Probe inserted AFTER the jump so it fires only on the fall-through arc.
    // The taken arc is covered by the visitLabel probe at the jump's target.
    // Unconditional GOTO and JSR do not produce fall-through probes.
    @Override
    public void visitJumpInsn(int opcode, Label label) {
      super.visitJumpInsn(opcode, label);
      if (opcode != Opcodes.GOTO && opcode != Opcodes.JSR)
        emitProbe();
    }

    // Probe inserted AFTER the label so it fires whenever any jump reaches
    // this basic-block entry. With SKIP_DEBUG, only branch-target and
    // exception-handler labels appear here (not line-number markers), so
    // every probe corresponds to a real control-flow edge.
    @Override
    public void visitLabel(Label label) {
      super.visitLabel(label);
      emitProbe();
    }
  }
}
