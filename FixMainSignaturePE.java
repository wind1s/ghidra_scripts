//Auto-renames and retypes the main function in Windows PE files.
//Method: Exit Anchoring + Callback Unwrapping + Size-Restricted MZ Scanner
//Constraint: Respects explicit 'void' signatures set by the user.
//@author windis
//@category Custom
//@keybinding
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.LinkedList;
import java.util.Set;
import java.util.HashSet;

public class FixMainSignaturePE extends GhidraScript {

    private class FuncNode {
        Function func;
        int depth;
        FuncNode(Function f, int d) { this.func = f; this.depth = d; }
    }

    @Override
    public void run() throws Exception {
        Function mainFunc = getFastGlobalFunction("main");

        if (mainFunc == null) {
            println("[*] 'main' not found. Scanning PE entry wrappers...");
            mainFunc = findWindowsMainViaInstructions();

            if (mainFunc != null) {
                mainFunc.setName("main", SourceType.USER_DEFINED);
                println("[+] Renamed function at " + mainFunc.getEntryPoint() + " to 'main'");
            }
        }

        if (mainFunc != null) {
            applyMainSignature(mainFunc);
        } else {
            println("[-] Failed to locate main function. The binary might be packed or highly obfuscated.");
        }
    }

    private Function findWindowsMainViaInstructions() {
        Function startFunc = getEntryPoint();

        if (startFunc == null) {
            println("[-] Could not locate the program entry point.");
            return null;
        }

        Queue<FuncNode> queue = new LinkedList<>();
        Set<Address> visited = new HashSet<>();

        queue.add(new FuncNode(startFunc, 0));
        visited.add(startFunc.getEntryPoint());

        Function exitAnchorCandidate = null;
        Function callbackCandidate = null;
        Function largestPayloadCandidate = null;

        long maxPayloadSize = 0;
        int nodesProcessed = 0;

        while (!queue.isEmpty() && nodesProcessed < 150) {
            FuncNode node = queue.poll();
            nodesProcessed++;
            Function currentFunc = node.func;

            if (node.depth > 4) continue;

            InstructionIterator instIter = currentProgram.getListing().getInstructions(currentFunc.getBody(), true);
            Function lastValidCall = null;

            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                Reference[] refs = inst.getReferencesFrom();

                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    if (toAddr == null || !toAddr.isMemoryAddress()) continue;

                    Function target = getFunctionAt(toAddr);
                    if (target == null || target.equals(currentFunc)) continue;

                    target = resolveThunk(target);
                    String targetName = target.getName().toLowerCase();

                    // FLOW REFERENCES (Standard Calls)
                    if (ref.getReferenceType().isCall()) {

                        // The Exit Anchor Trigger
                        if (targetName.equals("exit") || targetName.equals("_exit") || targetName.equals("_cexit")) {
                            if (exitAnchorCandidate == null && lastValidCall != null) {
                                exitAnchorCandidate = lastValidCall;
                            }
                        }

                        // Ignored if it's external or hits our Boilerplate heuristic
                        if (!target.isExternal() && !isCompilerBoilerplate(target)) {

                            lastValidCall = target;

                            if (!visited.contains(target.getEntryPoint())) {
                                visited.add(target.getEntryPoint());
                                queue.add(new FuncNode(target, node.depth + 1));

                                if (node.depth >= 1 && !isWrapper(targetName)) {
                                    long size = target.getBody().getNumAddresses();
                                    if (size > maxPayloadSize && size > 40) {
                                        maxPayloadSize = size;
                                        largestPayloadCandidate = target;
                                    }
                                }
                            }
                        }
                    }
                    // DATA REFERENCES (Pointer Callbacks)
                    else if (ref.getReferenceType().isData() || ref.getReferenceType().isIndirect()) {
                        if (!target.isExternal() && !isCompilerBoilerplate(target) && node.depth >= 1) {
                            if (callbackCandidate == null) {
                                callbackCandidate = target;
                            }
                        }
                    }
                }
            }
        }

        // The Exit Anchor (Highest Reliability for C/C++)
        if (exitAnchorCandidate != null) {
            long anchorSize = exitAnchorCandidate.getBody().getNumAddresses();

            // Rust/Go/Modern C++ Check: If the anchor is a tiny pathway wrapper, peek inside it for the real pointer.
            if (anchorSize < 150) {
                Function innerPointer = getPointerLoadInFunction(exitAnchorCandidate);
                if (innerPointer != null) {
                    println("[*] SUCCESS: Main identified via wrapper callback pointer -> " + innerPointer.getName());
                    return innerPointer;
                }
            }

            // Standard C: The anchor itself is the main payload.
            println("[*] SUCCESS: Main identified via exit() anchor -> " + exitAnchorCandidate.getName());
            return exitAnchorCandidate;
        }

        // Go-style global pointer fallback
        if (callbackCandidate != null) {
            println("[*] SUCCESS: Main identified via Pointer/Callback (Fallback pattern).");
            return callbackCandidate;
        }

        // Desperation Fallback
        if (largestPayloadCandidate != null) {
            println("[*] WARNING: Fallback to Largest Payload Analysis.");
            return largestPayloadCandidate;
        }

        return null;
    }

    // Peeks inside tiny wrapper functions to extract the callback pointer
    private Function getPointerLoadInFunction(Function f) {
        InstructionIterator instIter = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            for (Reference ref : inst.getReferencesFrom()) {
                if (ref.getReferenceType().isData() || ref.getReferenceType().isIndirect()) {
                    Address toAddr = ref.getToAddress();
                    if (toAddr != null && toAddr.isMemoryAddress()) {
                        Function target = getFunctionAt(toAddr);
                        if (target != null && !target.isExternal() && !target.equals(f)) {
                            if (!isCompilerBoilerplate(target)) {
                                return resolveThunk(target);
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    private Function resolveThunk(Function f) {
        while (f != null && f.isThunk()) {
            f = f.getThunkedFunction(true);
        }
        return f;
    }

    private Function getEntryPoint() {
        String[] entryNames = {"entry", "mainCRTStartup", "wmainCRTStartup", "WinMainCRTStartup", "wWinMainCRTStartup"};
        for (String name : entryNames) {
            Function f = getFastGlobalFunction(name);
            if (f != null) return f;
        }

        AddressIterator entryPoints = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        if (entryPoints.hasNext()) {
            return getFunctionAt(entryPoints.next());
        }
        return null;
    }

    // Identifies dead-end MSVC utilities using Name Matching AND Size-Restricted Assembly Parsing
    private boolean isCompilerBoilerplate(Function f) {
        String name = f.getName().toLowerCase();

        // Fast Name Check
        String[] junk = {
            "security", "cookie", "initterm", "matherr", "getmainargs", "managed_app",
            "cxx", "tls", "fls", "heap", "ioinit", "mtinit", "setargv", "cinit", "amsg", "rtc",
            "pre_c", "pe_img", "cexit", "error", "configthreadlocale", "guard", "environment",
            "vectored", "uninitialize", "register", "atexit", "handler", "lock", "narrow",
            "printf", "scanf", "puts", "gets", "malloc", "free", "strcmp", "strcpy", "strlen",
            "seh_prolog", "seh_epilog"
        };
        for (String j : junk) {
            if (name.contains(j)) return true;
        }

        // Size-Restricted Assembly Deep Scan
        // Only target functions smaller than 120 bytes to prevent false positives on massive wrappers.
        long size = f.getBody().getNumAddresses();
        if (size < 120) {
            InstructionIterator instIter = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                for (int i = 0; i < inst.getNumOperands(); i++) {
                    Object[] opObjs = inst.getOpObjects(i);
                    for (Object obj : opObjs) {
                        if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long val = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                            if (val == 0x5a4d || val == 0x4550) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    private boolean isWrapper(String name) {
        String[] wrappers = {
            "main", "start", "seh", "invoke", "crt"
        };
        for (String w : wrappers) {
            if (name.contains(w)) return true;
        }
        return false;
    }

    private void applyMainSignature(Function func) {
        if (func == null) return;

        Parameter[] currentParams = func.getParameters();
        SourceType source = func.getSignatureSource();
        String funcName = func.getName();

        println("[*] Applying signature to: " + funcName);

        try {
            DataType intType = IntegerDataType.dataType;

            if (currentParams.length == 0 && source == SourceType.USER_DEFINED) {
                println("[!] Skipping parameter update: explicitly defined as void by user.");
                return;
            }

            func.setReturnType(intType, SourceType.USER_DEFINED);
            func.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);

            DataType charType = CharDataType.dataType;
            DataType charPtr = new PointerDataType(charType);
            DataType charPtrPtr = new PointerDataType(charPtr);

            List<ParameterImpl> params = new ArrayList<>();
            params.add(new ParameterImpl("argc", intType, currentProgram));
            params.add(new ParameterImpl("argv", charPtrPtr, currentProgram));

            func.replaceParameters(
                params,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true,
                SourceType.USER_DEFINED
            );

            println("[+] Signature updated successfully.");

        } catch (Exception e) {
            println("[-] Error updating signature: " + e.getMessage());
        }
    }

    private Function getFastGlobalFunction(String name) {
        List<Function> funcs = getGlobalFunctions(name);
        if (funcs != null && !funcs.isEmpty()) {
            return funcs.get(0);
        }
        return null;
    }
}
