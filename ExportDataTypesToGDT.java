// Automatically exports user-defined program data types to a new GDT archive file.
// @author windis
// @category Custom
// @keybinding
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ExportDataTypesToGDT extends GhidraScript {

    @Override
    public void run() throws Exception {
        DataTypeManagerService service = state.getTool().getService(DataTypeManagerService.class);
        if (service == null) {
            println("[-] DataTypeManagerService is unavailable.");
            return;
        }

        DataTypeManager[] availableManagers = service.getDataTypeManagers();
        if (availableManagers.length == 0) {
            println("[-] No archives available to export.");
            return;
        }

        // Build a list of readable display names for dropdown menu
        List<String> archiveNames = new ArrayList<>();
        for (DataTypeManager manager : availableManagers) {
            archiveNames.add(manager.getName());
        }

        String chosenName = askChoice("Select Source Archive", "Which archive would you like to export?", archiveNames, archiveNames.get(0));
        if (chosenName == null) {
            println("[-] Export cancelled.");
            return;
        }

        // Find the matching DataTypeManager object based on the selected name
        DataTypeManager sourceManager = null;
        for (DataTypeManager manager : availableManagers) {
            if (manager.getName().equals(chosenName)) {
                sourceManager = manager;
                break;
            }
        }

        if (sourceManager == null) {
            println("[-] Error finding the selected archive.");
            return;
        }

        File gdtFile = askFile("Select Destination GDT Archive", "Save");
        if (gdtFile == null) {
            println("[-] Export cancelled.");
            return;
        }

        if (!gdtFile.getName().toLowerCase().endsWith(".gdt")) {
            gdtFile = new File(gdtFile.getAbsolutePath() + ".gdt");
        }

        if (gdtFile.exists()) {
            if (!askYesNo("Overwrite File", "The file already exists. Do you want to overwrite it?")) {
                println("[-] Export cancelled.");
                return;
            }
            gdtFile.delete();
        }

        println("[*] Exporting from [" + sourceManager.getName() + "] to: " + gdtFile.getAbsolutePath());
        FileDataTypeManager archiveManager = FileDataTypeManager.createFileArchive(gdtFile);

        int txId = archiveManager.startTransaction("Exporting types");
        int count = 0;

        try {
            Iterator<DataType> allTypes = sourceManager.getAllDataTypes();

            while (allTypes.hasNext()) {
                DataType dt = allTypes.next();
                String categoryPath = dt.getCategoryPath().getPath();

                if (categoryPath.startsWith("/BuiltInTypes")) {
                    continue;
                }

                archiveManager.addDataType(dt, null);
                count++;
            }

            println("[+] Successfully copied " + count + " data types to the archive!");

        } catch (Exception e) {
            println("[-] Error during export: " + e.getMessage());
        } finally {
            archiveManager.endTransaction(txId, true);
            archiveManager.save();
            archiveManager.close();
            println("[+] Archive saved and closed.");
        }
    }
}
