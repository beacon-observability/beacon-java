/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.pool.TypePool;
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

  private CallSiteVisitor(Map<String, Integer> scratch) {
    this.scratch = scratch;
  }

  static CallSiteVisitor forClass(TypeDescription type, ClassLoader loader) throws IOException {
    ClassFileLocator.Resolution resolution =
        ClassFileLocator.ForClassLoader.of(loader).locate(type.getName());
    if (!resolution.isResolved()) return null;
    Map<String, Integer> scratch = new HashMap<>();
    new ClassReader(resolution.resolve())
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public MethodVisitor visitMethod(
                  int access, String name, String desc, String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                  void reserve(String descriptor) {
                    int size = 8;
                    for (Type argument : Type.getArgumentTypes(descriptor))
                      size += argument.getSize();
                    scratch.merge(name + desc, size, Math::max);
                  }

                  @Override
                  public void visitMethodInsn(
                      int opcode,
                      String owner,
                      String method,
                      String descriptor,
                      boolean isInterface) {
                    if (CallSites.matches(owner, method)) reserve(descriptor);
                  }

                  @Override
                  public void visitInvokeDynamicInsn(
                      String method, String descriptor, Handle bootstrap, Object... arguments) {
                    if (bootstrap.getOwner().equals("java/lang/invoke/StringConcatFactory"))
                      reserve(descriptor);
                  }
                };
              }
            },
            ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    return scratch.isEmpty() ? null : new CallSiteVisitor(scratch);
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

      @Override
      public void visitSource(String file, String debug) {
        source = file == null ? "" : file;
        super.visitSource(file, debug);
      }

      @Override
      public MethodVisitor visitMethod(
          int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor original = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (original == null || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0)
          return original;
        Integer reserve = scratch.get(name + descriptor);
        if (reserve == null) return original;
        int first = (access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type argument : Type.getArgumentTypes(descriptor)) first += argument.getSize();
        return new Calls(
            original,
            first,
            reserve,
            type.getName() + "#" + name,
            source,
            access,
            name,
            descriptor,
            type.getInternalName());
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
    private int line = -1;
    private final List<Object> frameLocals = new ArrayList<>();

    Calls(
        MethodVisitor visitor,
        int first,
        int scratch,
        String location,
        String file,
        int access,
        String name,
        String descriptor,
        String owner) {
      super(Opcodes.ASM9, visitor);
      this.first = first;
      this.scratch = scratch;
      this.methodLocation = location;
      this.file = file;
      if ((access & Opcodes.ACC_STATIC) == 0)
        frameLocals.add(name.equals("<init>") ? Opcodes.UNINITIALIZED_THIS : owner);
      for (Type arg : Type.getArgumentTypes(descriptor)) {
        switch (arg.getSort()) {
          case Type.LONG:
            frameLocals.add(Opcodes.LONG);
            break;
          case Type.DOUBLE:
            frameLocals.add(Opcodes.DOUBLE);
            break;
          case Type.FLOAT:
            frameLocals.add(Opcodes.FLOAT);
            break;
          case Type.ARRAY:
            frameLocals.add(arg.getDescriptor());
            break;
          case Type.OBJECT:
            frameLocals.add(arg.getInternalName());
            break;
          default:
            frameLocals.add(Opcodes.INTEGER);
        }
      }
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
      for (int i = 0; i < mapped.length; i++) mapped[i] = remap(mapped[i]);
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
    public void visitFrame(int type, int count, Object[] locals, int stackCount, Object[] stack) {
      // Other agent visitors can supply compressed frames even when the reader expands
      // them. Track the original frame and emit a full frame with dead scratch locals.
      if (type == Opcodes.F_NEW || type == Opcodes.F_FULL) {
        frameLocals.clear();
        for (int i = 0; i < count; i++) frameLocals.add(locals[i]);
      } else if (type == Opcodes.F_APPEND) {
        for (int i = 0; i < count; i++) frameLocals.add(locals[i]);
      } else if (type == Opcodes.F_CHOP) {
        for (int i = 0; i < count; i++) frameLocals.remove(frameLocals.size() - 1);
      }
      List<Object> mapped = new ArrayList<>();
      int slot = 0;
      for (Object value : frameLocals) {
        if (slot == first) for (int j = 0; j < scratch; j++) mapped.add(Opcodes.TOP);
        mapped.add(value);
        slot += value == Opcodes.LONG || value == Opcodes.DOUBLE ? 2 : 1;
      }
      mv.visitFrame(Opcodes.F_FULL, mapped.size(), mapped.toArray(), stackCount, stack);
    }

    @Override
    public void visitMethodInsn(
        int opcode, String owner, String name, String descriptor, boolean isInterface) {
      if (!CallSites.matches(owner, name)) {
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
              if (literal == '\u0001' || literal == '\u0002') recipe.append('\u0002');
              recipe.append(literal);
            }
          } else recipe.append(ch);
        }
      } else {
        for (Type unused : Type.getArgumentTypes(descriptor)) recipe.append('\u0001');
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
      for (int i = args.length - 1; i >= 0; i--)
        mv.visitVarInsn(args[i].getOpcode(Opcodes.ISTORE), slots[i]);
      boolean instance = opcode != Opcodes.INVOKESTATIC;
      boolean constructor = name.equals("<init>");
      if (instance && !constructor) mv.visitVarInsn(Opcodes.ASTORE, receiver);
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
      if (instance && !constructor) mv.visitVarInsn(Opcodes.ALOAD, receiver);
      else mv.visitInsn(Opcodes.ACONST_NULL);
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
      if (constructor) mv.visitInsn(Opcodes.DUP);
      else if (instance) mv.visitVarInsn(Opcodes.ALOAD, receiver);
      for (int i = 0; i < args.length; i++)
        mv.visitVarInsn(args[i].getOpcode(Opcodes.ILOAD), slots[i]);
      if (bootstrap == null) mv.visitMethodInsn(opcode, owner, name, desc, isInterface);
      else mv.visitInvokeDynamicInsn(name, desc, bootstrap, constants);
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
      if (returned.getSort() != Type.VOID)
        mv.visitVarInsn(returned.getOpcode(Opcodes.ISTORE), result);
      mv.visitVarInsn(Opcodes.ALOAD, token);
      if (returned.getSort() != Type.VOID) {
        mv.visitVarInsn(returned.getOpcode(Opcodes.ILOAD), result);
        box(returned);
      } else if (instance) mv.visitVarInsn(Opcodes.ALOAD, receiver);
      else mv.visitInsn(Opcodes.ACONST_NULL);
      mv.visitMethodInsn(
          Opcodes.INVOKESTATIC, BRIDGE, "after", "(Ljava/lang/Object;Ljava/lang/Object;)V", false);
      if (returned.getSort() != Type.VOID)
        mv.visitVarInsn(returned.getOpcode(Opcodes.ILOAD), result);
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
