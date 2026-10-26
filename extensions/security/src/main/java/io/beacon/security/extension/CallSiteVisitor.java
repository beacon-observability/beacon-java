/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import java.io.IOException;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.AsmClassWriter;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.TypePath;

final class CallSiteVisitor extends AsmVisitorWrapper.AbstractBase {
  private static final String BRIDGE = "io/beacon/security/bridge/SecurityBridge";
  private final Map<String, Integer> scratch;
  private final Set<String> connectionOwners;

  private CallSiteVisitor(Map<String, Integer> scratch, Set<String> connectionOwners) {
    this.scratch = scratch;
    this.connectionOwners = connectionOwners;
  }

  static CallSiteVisitor forClass(TypeDescription type, ClassLoader loader) throws IOException {
    ClassFileLocator.Resolution resolution =
        ClassFileLocator.ForClassLoader.of(loader).locate(type.getName());
    if (!resolution.isResolved()) {
      return null;
    }
    Map<String, Integer> scratch = new HashMap<>();
    Set<String> connectionOwners = new HashSet<>();
    Map<String, Boolean> connectionTypes = new HashMap<>();
    TypePool pool = TypePool.Default.of(loader);
    new ClassReader(resolution.resolve())
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public MethodVisitor visitMethod(
                  int access, String name, String desc, String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                  void reserve(String descriptor) {
                    int size = 8;
                    for (Type argument : Type.getArgumentTypes(descriptor)) {
                      size += argument.getSize();
                    }
                    scratch.merge(name + desc, size, Math::max);
                  }

                  @Override
                  public void visitMethodInsn(
                      int opcode,
                      String owner,
                      String method,
                      String descriptor,
                      boolean isInterface) {
                    boolean matches = CallSites.matches(owner, method);
                    if (!matches && CallSites.isUrlConnectionMethod(method)) {
                      matches =
                          connectionTypes.computeIfAbsent(
                              owner,
                              name -> {
                                try {
                                  return pool.describe(name.replace('/', '.'))
                                      .resolve()
                                      .isAssignableTo(URLConnection.class);
                                } catch (RuntimeException ignored) {
                                  return false;
                                }
                              });
                      if (matches) {
                        connectionOwners.add(owner);
                      }
                    }
                    if (matches) {
                      reserve(descriptor);
                    }
                  }

                  @Override
                  public void visitInvokeDynamicInsn(
                      String method, String descriptor, Handle bootstrap, Object... arguments) {
                    if (bootstrap.getOwner().equals("java/lang/invoke/StringConcatFactory")) {
                      reserve(descriptor);
                    }
                  }
                };
              }
            },
            ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    return scratch.isEmpty() ? null : new CallSiteVisitor(scratch, connectionOwners);
  }

  @Override
  public int mergeWriter(int flags) {
    return flags | ClassWriter.COMPUTE_MAXS;
  }

  @Override
  public int mergeReader(int flags) {
    return flags & ~(ClassReader.SKIP_FRAMES | ClassReader.EXPAND_FRAMES);
  }

  @Override
  public ClassVisitor wrap(
      TypeDescription type,
      ClassVisitor visitor,
      Implementation.Context context,
      TypePool pool,
      FieldList<FieldDescription.InDefinedShape> fields,
      MethodList<?> methods,
      int writerFlags,
      int readerFlags) {
    return new ClassVisitor(Opcodes.ASM9, visitor) {
      String source = "";
      int version;
      String superName = "java/lang/Object";
      String[] interfaces = new String[0];

      @Override
      public void visit(
          int version,
          int access,
          String name,
          String signature,
          String superName,
          String[] interfaces) {
        this.version = version;
        this.superName = superName;
        this.interfaces = interfaces;
        super.visit(version, access, name, signature, superName, interfaces);
      }

      @Override
      public void visitSource(String file, String debug) {
        source = file == null ? "" : file;
        super.visitSource(file, debug);
      }

      @Override
      public MethodVisitor visitMethod(
          int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor original = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (original == null || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
          return original;
        }
        Integer reserve = scratch.get(name + descriptor);
        if (reserve == null) {
          return original;
        }
        int first = (access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type argument : Type.getArgumentTypes(descriptor)) {
          first += argument.getSize();
        }
        // Compute frames only for this method's security call sites, before passing it to
        // other visitors. A class-wide COMPUTE_FRAMES also recomputes unrelated tracing advice,
        // whose injected helpers are not available as class resources in the application pool.
        ClassWriter frames =
            new AsmClassWriter.FrameComputingClassWriter(ClassWriter.COMPUTE_FRAMES, pool);
        frames.visit(
            version, type.getModifiers(), type.getInternalName(), null, superName, interfaces);
        MethodVisitor buffered =
            frames.visitMethod(access, name, descriptor, signature, exceptions);
        return new MethodVisitor(
            Opcodes.ASM9,
            new Calls(
                buffered, first, reserve, type.getName() + "#" + name, source, connectionOwners)) {
          @Override
          public void visitEnd() {
            super.visitEnd();
            frames.visitEnd();
            new ClassReader(frames.toByteArray())
                .accept(
                    new ClassVisitor(Opcodes.ASM9) {
                      @Override
                      public MethodVisitor visitMethod(
                          int methodAccess,
                          String methodName,
                          String methodDescriptor,
                          String methodSignature,
                          String[] methodExceptions) {
                        return original;
                      }
                    },
                    0);
          }
        };
      }
    };
  }

  private static final class Calls extends MethodVisitor {
    // Reserve scratch slots before original locals; remap original locals instead of assuming a
    // maxLocals value.
    private final int scratch;
    private final int first;
    private final String methodLocation;
    private final String file;
    private final Set<String> connectionOwners;
    private int line = -1;

    Calls(
        MethodVisitor visitor,
        int first,
        int scratch,
        String location,
        String file,
        Set<String> connectionOwners) {
      super(Opcodes.ASM9, visitor);
      this.first = first;
      this.scratch = scratch;
      this.methodLocation = location;
      this.file = file;
      this.connectionOwners = connectionOwners;
    }

    private int remap(int index) {
      return index < first ? index : index + scratch;
    }

    @Override
    public void visitVarInsn(int opcode, int index) {
      mv.visitVarInsn(opcode, remap(index));
    }

    @Override
    public void visitIincInsn(int index, int increment) {
      mv.visitIincInsn(remap(index), increment);
    }

    @Override
    public void visitLocalVariable(
        String name, String desc, String sig, Label start, Label end, int index) {
      mv.visitLocalVariable(name, desc, sig, start, end, remap(index));
    }

    @Override
    public AnnotationVisitor visitLocalVariableAnnotation(
        int ref,
        TypePath path,
        Label[] start,
        Label[] end,
        int[] index,
        String desc,
        boolean visible) {
      int[] mapped = index.clone();
      for (int i = 0; i < mapped.length; i++) {
        mapped[i] = remap(mapped[i]);
      }
      return mv.visitLocalVariableAnnotation(ref, path, start, end, mapped, desc, visible);
    }

    @Override
    public void visitLineNumber(int number, Label start) {
      line = number;
      super.visitLineNumber(number, start);
    }

    @Override
    public void visitMaxs(int stack, int locals) {
      mv.visitMaxs(stack, locals + scratch);
    }

    @Override
    public void visitMethodInsn(
        int opcode, String owner, String name, String descriptor, boolean isInterface) {
      if (!CallSites.matches(owner, name)
          && !(connectionOwners.contains(owner) && CallSites.isUrlConnectionMethod(name))) {
        mv.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        return;
      }
      instrument(opcode, owner, name, descriptor, isInterface, null, null, null);
    }

    @Override
    public void visitInvokeDynamicInsn(
        String name, String descriptor, Handle bootstrap, Object... arguments) {
      if (!bootstrap.getOwner().equals("java/lang/invoke/StringConcatFactory")) {
        mv.visitInvokeDynamicInsn(name, descriptor, bootstrap, arguments);
        return;
      }
      StringBuilder recipe = new StringBuilder();
      if (name.equals("makeConcatWithConstants")
          && arguments.length > 0
          && arguments[0] instanceof String) {
        int constant = 1;
        for (char ch : ((String) arguments[0]).toCharArray()) {
          if (ch == '\u0002' && constant < arguments.length) {
            for (char literal : String.valueOf(arguments[constant++]).toCharArray()) {
              if (literal == '\u0001' || literal == '\u0002') {
                recipe.append('\u0002');
              }
              recipe.append(literal);
            }
          } else {
            recipe.append(ch);
          }
        }
      } else {
        for (Type unused : Type.getArgumentTypes(descriptor)) {
          recipe.append('\u0001');
        }
      }
      instrument(
          Opcodes.INVOKESTATIC,
          bootstrap.getOwner(),
          name,
          descriptor,
          false,
          bootstrap,
          arguments,
          recipe.toString());
    }

    private void instrument(
        int opcode,
        String owner,
        String name,
        String desc,
        boolean isInterface,
        Handle bootstrap,
        Object[] constants,
        String recipe) {
      Type[] args = Type.getArgumentTypes(desc);
      Type returned = Type.getReturnType(desc);
      int[] slots = new int[args.length];
      int next = first;
      for (int i = 0; i < args.length; i++) {
        slots[i] = next;
        next += args[i].getSize();
      }
      int receiver = next++;
      int array = next++;
      int token = next++;
      int result = next;
      for (int i = args.length - 1; i >= 0; i--) {
        mv.visitVarInsn(args[i].getOpcode(Opcodes.ISTORE), slots[i]);
      }
      boolean instance = opcode != Opcodes.INVOKESTATIC;
      boolean constructor = name.equals("<init>");
      if (instance && !constructor) {
        mv.visitVarInsn(Opcodes.ASTORE, receiver);
      }
      Label inactive = new Label();
      Label invoke = new Label();
      mv.visitMethodInsn(Opcodes.INVOKESTATIC, BRIDGE, "active", "()Z", false);
      mv.visitJumpInsn(Opcodes.IFEQ, inactive);
      push(args.length);
      mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
      for (int i = 0; i < args.length; i++) {
        mv.visitInsn(Opcodes.DUP);
        push(i);
        mv.visitVarInsn(args[i].getOpcode(Opcodes.ILOAD), slots[i]);
        box(args[i]);
        mv.visitInsn(Opcodes.AASTORE);
      }
      mv.visitVarInsn(Opcodes.ASTORE, array);
      mv.visitLdcInsn(owner);
      mv.visitLdcInsn(name);
      mv.visitLdcInsn(recipe == null ? desc : recipe);
      if (instance && !constructor) {
        mv.visitVarInsn(Opcodes.ALOAD, receiver);
      } else {
        mv.visitInsn(Opcodes.ACONST_NULL);
      }
      mv.visitVarInsn(Opcodes.ALOAD, array);
      mv.visitLdcInsn(methodLocation + "(" + file + (line < 0 ? "" : ":" + line) + ")");
      mv.visitLdcInsn(
          Type.getObjectType(
              methodLocation.substring(0, methodLocation.indexOf('#')).replace('.', '/')));
      mv.visitMethodInsn(
          Opcodes.INVOKESTATIC,
          BRIDGE,
          "before",
          "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;",
          false);
      mv.visitVarInsn(Opcodes.ASTORE, token);
      mv.visitJumpInsn(Opcodes.GOTO, invoke);
      mv.visitLabel(inactive);
      mv.visitInsn(Opcodes.ACONST_NULL);
      mv.visitVarInsn(Opcodes.ASTORE, token);
      mv.visitLabel(invoke);
      if (constructor) {
        mv.visitInsn(Opcodes.DUP);
      } else if (instance) {
        mv.visitVarInsn(Opcodes.ALOAD, receiver);
      }
      for (int i = 0; i < args.length; i++) {
        mv.visitVarInsn(args[i].getOpcode(Opcodes.ILOAD), slots[i]);
      }
      if (bootstrap == null) {
        mv.visitMethodInsn(opcode, owner, name, desc, isInterface);
      } else {
        mv.visitInvokeDynamicInsn(name, desc, bootstrap, constants);
      }
      if (constructor) {
        mv.visitVarInsn(Opcodes.ALOAD, token);
        mv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            BRIDGE,
            "constructed",
            "(Ljava/lang/Object;Ljava/lang/Object;)V",
            false);
        return;
      }
      if (returned.getSort() != Type.VOID) {
        mv.visitVarInsn(returned.getOpcode(Opcodes.ISTORE), result);
      }
      Label complete = new Label();
      mv.visitVarInsn(Opcodes.ALOAD, token);
      mv.visitJumpInsn(Opcodes.IFNULL, complete);
      mv.visitVarInsn(Opcodes.ALOAD, token);
      if (returned.getSort() != Type.VOID) {
        mv.visitVarInsn(returned.getOpcode(Opcodes.ILOAD), result);
        box(returned);
      } else if (instance) {
        mv.visitVarInsn(Opcodes.ALOAD, receiver);
      } else {
        mv.visitInsn(Opcodes.ACONST_NULL);
      }
      mv.visitMethodInsn(
          Opcodes.INVOKESTATIC, BRIDGE, "after", "(Ljava/lang/Object;Ljava/lang/Object;)V", false);
      mv.visitLabel(complete);
      if (returned.getSort() != Type.VOID) {
        mv.visitVarInsn(returned.getOpcode(Opcodes.ILOAD), result);
      }
    }

    private void push(int number) {
      mv.visitLdcInsn(number);
    }

    private void box(Type type) {
      String wrapper;
      switch (type.getSort()) {
        case Type.BOOLEAN:
          wrapper = "java/lang/Boolean";
          break;
        case Type.BYTE:
          wrapper = "java/lang/Byte";
          break;
        case Type.CHAR:
          wrapper = "java/lang/Character";
          break;
        case Type.SHORT:
          wrapper = "java/lang/Short";
          break;
        case Type.INT:
          wrapper = "java/lang/Integer";
          break;
        case Type.FLOAT:
          wrapper = "java/lang/Float";
          break;
        case Type.LONG:
          wrapper = "java/lang/Long";
          break;
        case Type.DOUBLE:
          wrapper = "java/lang/Double";
          break;
        default:
          return;
      }
      mv.visitMethodInsn(
          Opcodes.INVOKESTATIC,
          wrapper,
          "valueOf",
          "(" + type.getDescriptor() + ")L" + wrapper + ";",
          false);
    }
  }
}
