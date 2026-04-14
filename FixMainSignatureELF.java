//Auto-renames and retypes the main function (locating it via _start/entry)
//Method: Scans assembly instructions in entry point for references to functions.
//Constraint: Respects explicit 'void' signatures set by the user.
//@author wind1s
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

import java.util.ArrayList;
import java.util.List;

public class FixMainSignatureELF extends GhidraScript {

    @Override
    public void run() throws Exception {

        // Try to find existing 'main'
        Function mainFunc = getFastGlobalFunction("main");

        // If no main, try to find it via _start / entry instructions
        if (mainFunc == null) {
            println("[*] 'main' not found. Searching via '_start' or 'entry' instructions...");
            mainFunc = findMainViaInstructions();

            if (mainFunc != null) {
                // Rename found function to main
                mainFunc.setName("main", SourceType.USER_DEFINED);
                println("[+] Renamed function at " + mainFunc.getEntryPoint() + " to 'main'");
            }
        }

        // If we have a main (either found or discovered), apply signature
        if (mainFunc != null) {
            applyMainSignature(mainFunc);
        } else {
            println("[-] Failed to locate main function.");
        }
    }

    private Function findMainViaInstructions() {
        Function startFunc = getFastGlobalFunction("_start");
        if (startFunc == null) startFunc = getFastGlobalFunction("entry");

        if (startFunc == null) {
            println("[-] Could not find '_start' or 'entry' symbol.");
            return null;
        }

        InstructionIterator instIter = currentProgram.getListing().getInstructions(startFunc.getBody(), true);

        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            Reference[] refs = inst.getReferencesFrom();

            for (Reference ref : refs) {
                if (ref.isMemoryReference()) {
                    Address toAddr = ref.getToAddress();
                    Function potentialMain = getFunctionAt(toAddr);

                    if (potentialMain != null) {
                        // Skip the _start function itself
                        if (potentialMain.equals(startFunc)) continue;

                        // Skip external imports and thunks (e.g. __gmon_start__)
                        if (potentialMain.isThunk() || potentialMain.isExternal()) continue;

                        String name = potentialMain.getName();

                        // Filter out known startup routines and compiler artifacts
                        if (!name.contains("libc_start_main") &&
                            !name.contains("csu_init") &&
                            !name.contains("csu_fini") &&
                            !name.startsWith("_")) { // Skips _init, _fini, etc.

                            println("[*] Found candidate via Instruction Reference: " + name + " @ " + toAddr);
                            return potentialMain;
                        }
                    }
                }
            }
        }
        return null;
    }

    private void applyMainSignature(Function func) {
        if (func == null) return;

        Parameter[] currentParams = func.getParameters();
        SourceType source = func.getSignatureSource();
        String funcName = func.getName();

        println("[*] Applying signature to: " + funcName);

        try {
            DataType intType = IntegerDataType.dataType;

            // Only skip if parameters are 0 AND it was explicitly set by the user.
            // (Auto-analyzed functions often have 0 params by default)
            if (currentParams.length == 0 && source == SourceType.USER_DEFINED) {
                println("[!] Skipping parameter update: " + funcName + " is explicitly defined as void by user.");
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

    // Optimized lookup using the Symbol Table instead of iterating the entire binary
    private Function getFastGlobalFunction(String name) {
        List<Function> funcs = getGlobalFunctions(name);
        if (funcs != null && !funcs.isEmpty()) {
            return funcs.get(0);
        }
        return null;
    }
}
